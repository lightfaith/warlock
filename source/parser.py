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
    suspicious = {}

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

        if self.category == 'sudo':
            if 'error' in self.attributes.keys():
                self.score = 9
                Message.mark_suspicious(self, 'sudo failed')
            else:
                self.score = 3

        elif self.category == 'su':
            if self.attributes['result'] == 'FAILED': 
                self.score = 9
                Message.mark_suspicious(self, 'su failed')
            else:
                self.score = 3
            del self.attributes['result']

        elif self.category in ('groupadd', 'useradd',):
            self.score = 4

        elif self.category in ('auth',):
            if 'result' in self.attributes.keys():
                if self.attributes['result'] == 'Failed': 
                    self.score = 9
                    Message.mark_suspicious(self, '\'SSH\' auth failed')
                else:
                    self.score = 2
                del self.attributes['result']
            elif 'error' in self.attributes.keys():
                self.score = 9
            else:
                self.score = 2
                # TODO fail with login

        elif self.category == 'kernel':
            if 'entered promiscuous mode' in self.message:
                self.score = 4
            elif 'segfault at ' in self.message:
                self.score = 7

        elif self.category == 'daemon':
            if self.attributes['service'] == 'login':
                if re.search(r'(A|a)uthentication failure', self.message):
                    self.score == 8
                    Message.mark_suspicious(self, '\'login\' auth failed')

        #
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
    def mark_suspicious(event, reason):
        for attribute in ('ip', 'user'):
            if attribute not in Message.suspicious.keys():
                Message.suspicious[attribute] = {}
            value = event.attributes.get(attribute)
            if value:
                if value not in Message.suspicious[attribute].keys():
                    Message.suspicious[attribute][value] = {}
                try:
                    Message.suspicious[attribute][value][reason] += 1
                except:
                    Message.suspicious[attribute][value][reason] = 1
    

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
        ('port', lambda x: x, ('port',)),
        ('pid', lambda x: int(x), ('pid',)),
        ('host', lambda x: x, ('host', 'hostname',)),
        ('user', lambda x: x, ('user', 'username')),
        ('sudouser', lambda x: x, ('sudouser',)),
        ('command', lambda x: x, ('command',)),
        ('error', lambda x: x, ('error',)),
        ('service', lambda x: x, ('service',)),
        ('result', lambda x: x, ('result',)),
    ]

    # patterns
    patterns = [(category, Grok(pattern), assertion) 
                for category, pattern, assertion in [
        ('apache-access', '^%{COMMONAPACHELOG}$', lambda source: re.search(r'access\.log(\.\d)?$', source)),
        ('apache-access', '^%{COMBINEDAPACHELOG}$', lambda source: re.search(r'access\.log(\.\d)?$', source)),
        ('apache-error', '^%{HTTPD_ERRORLOG}$', lambda source: re.search(r'error\.log(\.\d)?$', source)),

        # auth with SSH key or password
        ('auth', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} sshd(?:\\[%{POSINT:pid}\\])?: %{DATA:result} %{DATA:method} for (invalid user )?%{DATA:user} from %{IPORHOST:ip} port %{NUMBER:port} ssh2(: %{GREEDYDATA:signature})?', 
         lambda source: re.search(r'auth\.log(\.\d)?$', source)),
        # auth through login 
        ('auth', # TODO May  2 23:06:14 app-1 login[5130]: pam_unix(login:auth): authentication failure; logname=LOGIN uid=0 euid=0 tty=tty1 ruser= rhost=  user=user1                                                          
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} login(?:\\[%{POSINT:pid}\\])?: pam_unix%{GREEDYDATA}: %{DATA:event}; %{GREEDYDATA} user=%{GREEDYDATA:user}',
         lambda source: re.search(r'auth\.log(\.\d)?$', source)),
        # sshd reverse mapping fail
        ('auth', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} sshd(?:\\[%{POSINT:pid}\\])?: reverse mapping checking getaddrinfo for %{GREEDYDATA} \\[%{IPORHOST:ip}\\] failed - %{GREEDYDATA:error}',
         lambda source: re.search(r'auth\.log(\.\d)?$', source)),
        # sudo
        ('sudo', 
         "%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} sudo(?:\\[%{POSINT:pid}\\])?: \\s*%{DATA:user} :( %{DATA:error} ;)? TTY=%{DATA:tty} ; PWD=%{DATA:pwd} ; USER=%{DATA:sudouser} ; COMMAND=%{GREEDYDATA:command}", 
         lambda source: re.search(r'auth\.log(\.\d)?$', source)),
        # su
        ('su', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} su(?:\\[%{POSINT:pid}\\])?: %{GREEDYDATA:result} su for %{DATA:sudouser} by %{GREEDYDATA:user}',
         lambda source: re.search(r'auth\.log(\.\d)?$', source)),

        # user modification
        ('useradd', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} useradd(?:\\[%{POSINT:pid}\\])?: new user: name=%{DATA:user}, UID=%{NUMBER:uid}, GID=%{NUMBER:gid}, home=%{DATA:home}, shell=%{DATA:shell}$', 
         lambda source: re.search(r'auth\.log(\.\d)?$', source)),
        ('groupadd', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} groupadd(?:\\[%{POSINT:pid}\\])?: new group: name=%{DATA:group}, GID=%{NUMBER:gid}', 
         lambda source: re.search(r'auth\.log(\.\d)?$', source)),
        ('chsh', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} chsh(?:\\[%{POSINT:pid}\\])?: changed user `%{DATA:user}\' shell to `%{DATA:shell}\'',
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

