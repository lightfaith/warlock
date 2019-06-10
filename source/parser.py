#!/usr/bin/python3
import re
from pygrok import Grok
from dateutil.relativedelta import relativedelta
from datetime import datetime
from source import lib
from source import log
from threading import Thread
import pdb
import sqlite3
import traceback

class DB:
    def __init__(self, path):
        self.path = path
        self.uniques = {
            'source': {},
            'category': {},
            'attribute': {},
        }
        self.lasts = {
            'source' : 0,
            'category': 0,
            'attribute': 0,
            'entry': 0,
        }
        self.schema = (
"""
CREATE TABLE Source
(
	source_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	path VARCHAR(256) NOT NULL UNIQUE
);

CREATE TABLE Category
(
	category_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	name VARCHAR(50) NOT NULL UNIQUE
);

CREATE TABLE Entry
(
	entry_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	timestamp DATETIME NOT NULL,
	source_id INTEGER NOT NULL,
	category_id INTEGER NOT NULL,
	score INTEGER NOT NULL,
	severity VARCHAR(10) NOT NULL,
	message VARCHAR(16384) NOT NULL, 
	FOREIGN KEY(source_id) REFERENCES Source(source_id) ON DELETE CASCADE,
	FOREIGN KEY(category_id) REFERENCES Category(category_id) ON DELETE CASCADE
);


CREATE TABLE Attribute
(
	attribute_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	name VARCHAR(50) NOT NULL UNIQUE
);

CREATE TABLE EA
(
	entry_id INTEGER NOT NULL,
	attribute_id INTEGER NOT NULL,
	value VARCHAR(256) NOT NULL,
	PRIMARY KEY(entry_id, attribute_id),
	FOREIGN KEY(entry_id) REFERENCES Entry(entry_id) ON DELETE CASCADE,
	FOREIGN KEY(attribute_id) REFERENCES Attribute(attribute_id) ON DELETE CASCADE
);

CREATE INDEX timestamp_index ON Entry(timestamp);
CREATE INDEX score_index ON Entry(score);
CREATE INDEX severity_index ON Entry(severity);
CREATE INDEX attr_index ON EA(value);
"""
        )
        self.conn = sqlite3.connect(self.path)
        self.cur = self.conn.cursor()
        # create REGEXP function
        self.conn.create_function("REGEXP", 2, lambda x, y: re.search(x, y) is not None)
        # create schema
        self.query("PRAGMA foreign_keys=ON")
        for table in self.schema.split(';'):
            self.query(table)
    

    def commit(self):
        self.conn.commit()

    def query(self, command, parameters=None, commit=True):
        #print(command, parameters)
        if not command.strip():
            return []
        try:
            self.cur.execute(command, parameters or tuple())
        except:
            traceback.print_exc()
            print('QUERY:')
            print(command)
            print(parameters)
        if commit:
            self.commit()
        if command.upper().startswith('SELECT '):
            return self.cur.fetchall()
        return []

    def insert_message(self, message):
        # create source if necessary
        if message.source not in self.uniques['source'].keys():
            self.query("INSERT INTO Source(path) VALUES(?)", (message.source,), commit=False)
            self.lasts['source'] += 1
            source_id = self.lasts['source']
            self.uniques['source'][message.source] = source_id
        else:
            source_id = self.uniques['source'][message.source]
        # create category if necessary
        if message.category not in self.uniques['category'].keys():
            self.query("INSERT INTO Category(name) VALUES(?)", (message.category,), commit=False)
            self.lasts['category'] += 1
            category_id = self.lasts['category']
            self.uniques['category'][message.category] = category_id
        else:
            category_id = self.uniques['category'][message.category]
        
        # create entry
        self.query("INSERT INTO Entry(timestamp, source_id, category_id, score, "
                   "                  severity, message) "
                   "VALUES (?, ?, ?, ?, ?, ?)", 
                   (message.timestamp,
                    source_id,
                    category_id,
                    message.score,
                    message.severity,
                    message.message
                   ), commit=False)
        self.lasts['entry'] += 1
        entry_id = self.lasts['entry']

        # add entry-attributes for entry
        for attribute, value in message.attributes.items():
            # add attribute if necessary
            if attribute not in self.uniques['attribute'].keys():
                self.query("INSERT INTO Attribute(name) VALUES(?)", (attribute,), commit=False)
                self.lasts['attribute'] += 1
                attribute_id = self.lasts['attribute']
                self.uniques['attribute'][attribute] = attribute_id
            else:
                attribute_id = self.uniques['attribute'][attribute]
            self.query("INSERT INTO EA(entry_id, attribute_id, value) "
                       "VALUES(?, ?, ?)",
                       (entry_id,
                        attribute_id,
                        value), commit=False)
        return entry_id
    ##########
        

class MessageParserThread(Thread):
    def __init__(self, filename, lines):
        Thread.__init__(self)
        self.filename = filename
        self.lines = lines
        self.results = []

    def run(self):
        for line in self.lines:
            m = Message.parse(self.filename, line)
            if not m:
                continue
            self.results.append(m)





class Message:
    debug_parsing = False #or True
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
        self.db_id = 0            # ID of entry in DB, will be corrected
                                  # after DB insert
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

        elif self.category == 'sudo':
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

        elif self.category in ('groupadd', 'useradd', 'chsh', 'passwd', 
                               'chage', 'chfn', 'userdel', 'groupdel'):
            self.score = 4

        elif self.category in ('auth',):
            if 'result' in self.attributes.keys():
                if self.attributes['result'] == 'Failed': 
                    self.score = 9
                    Message.mark_suspicious(self, '\'SSH\' auth failed')
                else:
                    self.score = 2
                del self.attributes['result']
            elif ('event' in self.attributes.keys() 
                  and 'failure' in self.attributes['event']):
                self.score = 9
            else:
                self.score = 2
        elif self.category == 'cron-session':
            self.score = 2
            
        elif self.category == 'kernel':
            if 'entered promiscuous mode' in self.message:
                self.score = 4
            elif 'segfault at ' in self.message:
                self.score = 7

        elif self.category == 'daemon':
            if self.attributes['service'] == 'login':
                if re.search(r'(A|a)uthentication failure', self.message):
                    self.score = 8
                    Message.mark_suspicious(self, '\'login\' auth failed')
                else:
                    self.score = 2
            elif self.attributes['service'] in ('dhclient', 'ntpdate'):
                self.score = 2
            elif self.attributes['service'] == 'init':
                self.score = 4
            elif self.attributes['service'] in ('su', 'sudo'):
                self.score = 2
            elif self.attributes['service'] == 'mysqld_safe':
                if re.search(r'PLEASE REMEMBER TO SET A PASSWORD', self.message):
                    self.score = 6
            elif self.attributes['service'] == 'sshd':
                if 'error' in self.attributes.keys():
                    self.score = 7
                if re.search(r'error: Bind to port \d+ on .+ failed', self.message):
                    self.score = 4
                elif re.search('session (?:opened|closed) for user (\w+) by', self.message):
                    user = re.search('session (?:opened|closed) for user (\w+) by', self.message).group(1)
                    self.attributes['user'] = user
                    self.score = 2
                elif re.search('Server listening on .+ port (\d+).', self.message):
                    port = re.search('Server listening on .+ port (\d+).', self.message).group(1)
                    self.score = 1 if port == 22 else 4
                    
            # TODO mysql
            # TODO ntpd
            
            elif 'Timezone set to' in self.message:
                self.score = 4
        
        elif self.category == 'apache-access':
            if 400 <= self.attributes['response'] < 500:
                self.score = 5
            elif 500 <= self.attributes['response']:
                self.score = 6
            if 'other' in self.attributes.keys(): # unknown data appended
                self.score = 4
            if (self.attributes['response'] == 200 # WP failed login
                and self.attributes['method'] == 'POST'
                and self.attributes['request'].endswith('/wp-login.php')):
                self.score = 7
                Message.mark_suspicious(self, '\'WordPress\' auth failed')
        elif self.category == 'apache-error':
            if 'other' in self.attributes.keys(): # unknown data appended
                self.score = 4
            if 'error reading the headers' in self.message:
                self.score = 5

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
    def fancy_print(self):
        message_padded = '\n'.join(['    \u2502%-*s\u2502' 
                                    % (Message.print_len, x) 
                                    for x in [self.message[i:i+Message.print_len] 
                                              for i in range(0, 
                                                             len(self.message), 
                                                             Message.print_len)]])

        print('%s%s < %d > %s (from %s): \n%s\n%s\n%s\n    attr: %s%s' % (
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
            log.COLOR_NONE))

    def __str__(self):
        return self.message + ' (from %s)' % self.source

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
        for category, pattern, assertion, add in Message.patterns[start:end]:
            if not assertion(source):
                continue
            parsed = pattern.match(message)
            if parsed:
                if Message.debug_parsing:
                    log.info('  Matches %s' % pattern.pattern)
                    if category == 'UNKNOWN':
                        log.warn('    which is \'UNKNOWN\' format.')
                for k, v in add.items():
                    parsed[k] = v
                if Message.debug_parsing:
                    print(parsed)
                    print()
                """ return new Parser object """
                return Message(source, 
                               category, 
                               message, 
                               pattern.pattern, 
                               parsed)
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
        ('event', lambda x: x, ('event',)),
        ('service', lambda x: x, ('service',)),
        ('result', lambda x: x, ('result',)),
        ('other', lambda x: x, ('other',)),
        ('method', lambda x: x, ('verb',)),
        ('request', lambda x: x, ('request',)),
        ('response', lambda x: int(x), ('response',)),
    ]

    # patterns
    patterns = [(category, Grok(pattern), assertion, add) 
                for category, pattern, assertion, add in [
        ('apache-access', 
         '^%{COMMONAPACHELOG}$', 
         lambda source: ('www' in source 
                         or re.search(r'access\.log(\.\d)?$', source)),
         {}),
        ('apache-access', 
         '^%{COMBINEDAPACHELOG}$', 
         lambda source: ('www' in source 
                         or re.search(r'access\.log(\.\d)?$', source)),
         {}),
        ('apache-access', 
         '^%{COMBINEDAPACHELOG} %{GREEDYDATA:other}$', 
         lambda source: ('www' in source 
                         or re.search(r'access\.log(\.\d)?$', source)),
         {}),
        ('apache-error', 
         '^%{HTTPD_ERRORLOG}$', 
         lambda source: ('www' in source 
                         or re.search(r'error\.log(\.\d)?$', source)),
         {}),
        ('apache-error', 
         '^%{HTTPD_ERRORLOG} %{GREEDYDATA:other}$', 
         lambda source: ('www' in source 
                         or re.search(r'error(\.|_)log(\.\d)?$', source)),
         {}),

        # auth with SSH key or password
        ('auth', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} sshd(?:\\[%{POSINT:pid}\\])?: %{DATA:result} %{DATA:method} for (invalid user )?%{DATA:user} from %{IPORHOST:ip} port %{NUMBER:port} ssh2(: %{GREEDYDATA:signature})?', 
         lambda source: re.search(r'auth\.log(\.\d)?$', source),
         {}),
        # auth through login 
        ('auth', # TODO May  2 23:06:14 app-1 login[5130]: pam_unix(login:auth): authentication failure; logname=LOGIN uid=0 euid=0 tty=tty1 ruser= rhost=  user=user1                                                        
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} login(?:\\[%{POSINT:pid}\\])?: pam_unix%{GREEDYDATA}: %{DATA:event}; %{GREEDYDATA} user=%{GREEDYDATA:user}',
         lambda source: re.search(r'auth\.log(\.\d)?$', source),
         {}),
        # cron session
        ('cron-session', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} CRON(?:\\[%{POSINT:pid}\\])?: %{GREEDYDATA} session %{DATA} for user %{WORD:user}( by \\(uid=%{NUMBER:uid}\\))?',
         lambda source: re.search(r'auth\.log(\.\d)?$', source),
         {}),
        # sudo
        ('sudo', 
         "%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} sudo(?:\\[%{POSINT:pid}\\])?: \\s*%{DATA:user} :( %{DATA:error} ;)? TTY=%{DATA:tty} ; PWD=%{DATA:pwd} ; USER=%{DATA:sudouser} ; COMMAND=%{GREEDYDATA:command}", 
         lambda source: re.search(r'auth\.log(\.\d)?$', source),
         {}),
        # su
        ('su', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} su(?:\\[%{POSINT:pid}\\])?: %{GREEDYDATA:result} su for %{DATA:sudouser} by %{GREEDYDATA:user}',
         lambda source: re.search(r'auth\.log(\.\d)?$', source),
         {}),

        # user modification
        ('useradd', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} useradd(?:\\[%{POSINT:pid}\\])?: new user: name=%{DATA:user}, UID=%{NUMBER:uid}, GID=%{NUMBER:gid}, home=%{DATA:home}, shell=%{DATA:shell}$', 
         lambda source: re.search(r'auth\.log(\.\d)?$', source),
         {}),
        ('groupadd', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} groupadd(?:\\[%{POSINT:pid}\\])?: new group: name=%{DATA:group}, GID=%{NUMBER:gid}', 
         lambda source: re.search(r'auth\.log(\.\d)?$', source),
         {}),
        ('chsh', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} chsh(?:\\[%{POSINT:pid}\\])?: changed user `%{DATA:user}\' shell to `%{DATA:shell}\'',
         lambda source: re.search(r'auth\.log(\.\d)?$', source),
         {}),
        ('passwd', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} passwd(?:\\[%{POSINT:pid}\\])?: %{GREEDYDATA} password changed for %{GREEDYDATA:user}',
         lambda source: re.search(r'auth\.log(\.\d)?$', source),
         {}),
        ('passwd', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} usermod(?:\\[%{POSINT:pid}\\])?: change user `%{DATA:user}\' password',
         lambda source: re.search(r'auth\.log(\.\d)?$', source),
         {}),
        ('chage', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} chage(?:\\[%{POSINT:pid}\\])?: changed password expiry for %{GREEDYDATA:user}',
         lambda source: re.search(r'auth\.log(\.\d)?$', source),
         {}),
        ('chfn', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} chfn(?:\\[%{POSINT:pid}\\])?: changed user `%{DATA:user}\' information',
         lambda source: re.search(r'auth\.log(\.\d)?$', source),
         {}),
        ('userdel', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} userdel(?:\\[%{POSINT:pid}\\])?: delete user `%{DATA:user}\'',
         lambda source: re.search(r'auth\.log(\.\d)?$', source),
         {}),
        ('groupdel', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} userdel(?:\\[%{POSINT:pid}\\])?: removed group `%{DATA:group}\' owned by `%{DATA:user}\'',
         lambda source: re.search(r'auth\.log(\.\d)?$', source),
         {}),

        # kernel         
        ('kernel', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} kernel: ', 
         lambda source: re.search(r'kern\.log(\.\d)?$', source),
         {}),
        ('kernel', 
         '', 
         lambda source: re.search(r'dmesg(\.\d)?$', source),
         {}),

        ('tor', 
         '%{SYSLOGTIMESTAMP:timestamp}', 
         lambda source: re.search(r'tor/debug\.log(\.\d)?$', source),
         {}),
        
        #########
        # DAEMON
        #########
        # sshd reverse mapping fail
        ('daemon', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} sshd(?:\\[%{POSINT:pid}\\])?: reverse mapping checking getaddrinfo for %{GREEDYDATA} \\[%{IPORHOST:ip}\\] failed - %{GREEDYDATA:error}',
         lambda source: re.search(r'auth\.log(\.\d)?$', source),
         {'service': 'sshd'}),

        # generic daemon
        ('daemon', 
         '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} %{DATA:service}(?:\\[%{POSINT:pid}\\])?: ', 
         lambda source: True,
         {}),

        ####
        # last resort for timed events
        ####
        ('UNKNOWN', '%{SYSLOGTIMESTAMP:timestamp}', lambda source: True, {}),
    ]]

