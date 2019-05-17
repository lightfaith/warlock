#!/usr/bin/python3
import re
from pygrok import Grok
from dateutil.relativedelta import relativedelta
from datetime import datetime
from source import lib
from source import log
from threading import Thread

class MessageParserThread(Thread):
    def __init__(self, filename, lines):
        Thread.__init__(self)
        self.filename = filename
        self.lines = lines
        self.result = []
        #print(self, '%d lines' % len(lines))

    def run(self):
        for line in self.lines:
            self.result.append(Message.parse(self.filename, line))
        #print(self, 'done.')


class Message:
    debug_parsing = False

    def __init__(self, source, category, message, grok_pattern, parsed):
        self.source = source      # filename
        self.category = category  # log type (from Message.patterns)
        self.score = 0            # criticality, will be assessed
        self.severity = 'UNKNOWN' # score meaning
        self.timestamp = None     # timestamp, will be extracted 
                                  # from self.parsed
        self.message = message    # raw message
        self.grok_pattern = grok_pattern # matched pattern
        self.parsed = parsed      # grok result dict, important stuff will be 
                                  # extracted into time and attributes
        self.attributes = {}      # dict of interesting data (e.g. IP, username)
                                  # from self.parsed
        self.analyze()

    def analyze(self):
        for attribute, reformatter, keys in Message.attributes:
            for key in keys:
                if key in self.parsed.keys():
                    value = self.parsed[key]
                    if value is None:
                        continue
                    # save time as self.timestamp,
                    # other as attributes
                    if attribute == 'timestamp':
                        self.timestamp = reformatter(value)
                        #if self.timestamp > lib.normalize_datetime(): # TODO mtime, subtracted...
                        #    self.timestamp += relativedelta(years=-1)
                        if Message.debug_parsing:
                            log.info('  Added timestamp: %s' % self.timestamp)
                    else:
                        if Message.debug_parsing:
                            log.info('  Adding %s: %s as %s attribute' 
                                     % (key, value, attribute))
                        self.attributes[attribute] = reformatter(value)

        if self.category == 'kernel':
            self.attributes['service'] = 'kernel'

        # TODO set score
        if self.category == 'sudo':
            # TODO mark failing users as suspicious
            if 'error' in self.attributes.keys():
                self.score = 9
            else:
                self.score = 2
        elif self.category in ('groupadd', 'useradd',):
            self.score = 4
        elif self.category in ('auth',):
            self.score = 2

        # set severity based on score
        if self.score >= 8:
            self.severity = 'critical'
        elif self.score >= 5:
            self.severity = 'warning'
        elif self.score >= 3:
            self.severity = 'notice'
        elif self.score >= 1:
            self.severity = 'info'
        elif self.category == 'UNKNOWN':
            self.severity = 'UNKNOWN'
        else:
            self.severity = 'none'
            
        
    
    #################################################
    def __str__(self):
        message_padded = '\n'.join(['    \u2502%-*s\u2502' % (Message.print_len, x) for x in [self.message[i:i+Message.print_len] for i in range(0, len(self.message), Message.print_len)]])

        return '%s%s < %d > %s (from %s): \n%s\n%s\n%s\n    attr: %s%s' % (
            lib.severity_colors[self.severity],
            lib.normalize_datetime(self.timestamp),
            #self.timestamp,
            self.score,
            self.category,
            self.source,
            '    \u250c' + '\u2500' * Message.print_len + '\u2510',
            message_padded,
            '    \u2514' + '\u2500' * Message.print_len + '\u2518',
            self.attributes,
            log.COLOR_NONE)

    ######################################################################
    @staticmethod
    def parse(source, message):
        # define interval (TODO from source)
        # TODO if nothing test all
        start = 0
        end = len(Message.patterns)

        if Message.debug_parsing:
            log.info('Parsing message: %s%s%s' 
                     % (log.COLOR_GREY, message, log.COLOR_NONE))
        for category, pattern, assertion in Message.patterns[start:end]:
            if not assertion(source):
                continue
            parsed = pattern.match(message)
            if parsed:
                if Message.debug_parsing:
                    log.info('  Matches %s' % pattern.pattern)
                    if category == 'UNKNOWN':
                        log.warn('    which is \'UNKNOWN\' format.')
                #print(parsed)
                #print()
                """ return new Parser object """
                return Message(source, category, message, pattern.pattern, parsed)
        if Message.debug_parsing:
            log.warn('  No match, no timestamp!')
        return None

    ######################################################################
    print_len = 100
    
    # GROK attributes
    attributes = [
        ('timestamp', lambda x: lib.normalize_datetime(x), ('timestamp', 'time')),
        ('ip', lambda x: x, ('clientip', 'ip')),
        ('pid', lambda x: int(x), ('pid',)),
        ('host', lambda x: x, ('host', 'hostname',)),
        ('user', lambda x: x, ('user', 'username')),
        ('sudouser', lambda x: x, ('sudouser',)),
        ('command', lambda x: x, ('command',)),
        ('error', lambda x: x, ('error',)),
        ('service', lambda x: x, ('service',)),
    ]

    # patterns
    patterns = [(category, Grok(pattern), assertion) 
                for category, pattern, assertion in [
        ('apache-access', '^%{COMMONAPACHELOG}$', lambda source: re.search(r'access\.log(\.\d)?$', source)),
        ('apache-access', '^%{COMBINEDAPACHELOG}$', lambda source: re.search(r'access\.log(\.\d)?$', source)),
        ('apache-error', '^%{HTTPD_ERRORLOG}$', lambda source: re.search(r'error\.log(\.\d)?$', source)),

        ('auth', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} sshd(?:\\[%{POSINT:pid}\\])?: %{DATA:event} %{DATA:method} for (invalid user )?%{DATA:user} from %{IPORHOST:ip} port %{NUMBER:port} ssh2(: %{GREEDYDATA:signature})?', 
         lambda source: re.search(r'auth\.log(\.\d)?$', source)),
        ('sudo', 
         "%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} sudo(?:\\[%{POSINT:pid}\\])?: \\s*%{DATA:user} :( %{DATA:error} ;)? TTY=%{DATA:tty} ; PWD=%{DATA:pwd} ; USER=%{DATA:sudouser} ; COMMAND=%{GREEDYDATA:command}", 
         lambda source: re.search(r'auth\.log(\.\d)?$', source)),
        ('useradd', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} useradd(?:\\[%{POSINT:pid}\\])?: new user: name=%{DATA:name}, UID=%{NUMBER:uid}, GID=%{NUMBER:gid}, home=%{DATA:home}, shell=%{DATA:shell}$', 
         lambda source: re.search(r'auth\.log(\.\d)?$', source)),
        ('groupadd', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} groupadd(?:\\[%{POSINT:pid}\\])?: new group: name=%{DATA:name}, GID=%{NUMBER:gid}', 
         lambda source: re.search(r'auth\.log(\.\d)?$', source)),
        
        ('kernel', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} kernel: ', 
         lambda source: re.search(r'kern\.log(\.\d)?$', source)),
        ('kernel', 
         '', 
         lambda source: re.search(r'dmesg(\.\d)?$', source)),
        ('tor', 
         '%{SYSLOGTIMESTAMP:timestamp}', 
         lambda source: re.search(r'tor/debug\.log(\.\d)?$', source)),
        
        # generic daemon
        ('daemon', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} %{DATA:service}(?:\\[%{POSINT:pid}\\])?: ', 
         lambda source: True),

        # last resort for timed events
        ('UNKNOWN', '%{SYSLOGTIMESTAMP:timestamp}', lambda source: True),
    ]]

