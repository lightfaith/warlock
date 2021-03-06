#!/usr/bin/python3
import pdb
import re
from source import lib
from source import log
import traceback
from time import sleep

from collections import OrderedDict
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.ticker as ticker
from venn import venn as venn_diagram

from source.parser import Message

def list_events(events, display_filter_str):
    #print('display_filter_str: "%s"' % display_filter_str)
    display_filter = None
    count = 0
    try:
        first_word = display_filter_str.split()[0]
    except:
        first_word = ''
    if first_word.isdigit():
        display_filter = Filter.parse(display_filter_str[len(first_word):])
        count = int(first_word)
        #print('Set count:', count, 'filter is', display_filter)
    #if not display_filter:
    if not count:
        display_filter = Filter.parse(display_filter_str)
        #print('Filter is', display_filter)
    
    #print(count, display_filter)
    i = 0
    matches = display_filter.run() if display_filter else events.keys()
    for db_id in matches or []:
        event = events[db_id]
        #if (not display_filter) or display_filter.test(event):
        event.fancy_print()
        i += 1
        if count and i >= count:
            break


def list_suspicious(events, what, display_filter_str):
    if what in Message.suspicious.keys():
        problems = lib.natural_sort(Message.suspicious[what].items(), key = lambda x: x[0])
        for troublemaker, incidents in problems:
            try:
                incident_count = max(count for _,count in incidents.items()) # TODO or sum
                if incident_count > 5:
                    suspicious_color = log.COLOR_RED
                elif incident_count > 2:
                    suspicious_color = log.COLOR_BROWN
                else:
                    suspicious_color = log.COLOR_YELLOW
            except:
                #traceback.print_exc()
                incidents = None
                suspicious_color = log.COLOR_NONE

            print('%s%s%s' % (suspicious_color, troublemaker, log.COLOR_NONE))
            if incidents:
                for incident, count in incidents.items():
                    print('- %s (%d)' % (incident, count))
        print('\u2500' * 15)
        print('TOTAL:',len(problems))


def list_overview(events, what, display_filter_str):
    severities = ('UNKNOWN', 'none', 'info', 'notice', 'warning', 'critical')
    d = {} if what == 'attributes' else {'{NONE}': []}

    display_filter = Filter.parse(display_filter_str)
    matches = display_filter.run() if display_filter else events.keys()

    for db_id in matches or []:
        event = events[db_id]

        dynamic = {
            'source': event.source,
            'category': event.category,
        }

        if what == 'attributes':
            for attr in event.attributes.keys():
                if attr not in d.keys():
                    d[attr] = []
                d[attr].append(event)
        else:
            matched = False
            for source in (dynamic, event.attributes):
                if what in source.keys():
                    if source[what] not in d.keys():
                        d[source[what]] = []
                    d[source[what]].append(event)
                    matched = True
                    break

            if not matched:
                d['{NONE}'].append(event) 

    param_max_len = max([0] + [len(str(k)) for k in d.keys()] + [len(what)])
    print('%s%-*s%s' % (log.COLOR_BLUE, param_max_len, what.upper(), log.COLOR_NONE), 
          '  '.join('%s%8s%s' 
                    % (lib.severity_colors[s], s, log.COLOR_NONE) 
                    for s in severities), 
          '\u2502 %sTOTAL%s' % (log.COLOR_BLUE, log.COLOR_NONE)
          )

    severity_totals = [0 for s in severities]

    for parameter in lib.natural_sort(d.keys()):
        events = d[parameter]
        counters = [0 for s in severities]
        for event in events:
            counters[severities.index(event.severity)] += 1
        if sum(counters) == 0:
            continue

        # add counters to severity totals
        for i in range(len(counters)):
            severity_totals[i] += counters[i]
        
            
        print('%-*s' % (param_max_len, 
                        parameter), 
              '  '.join('%s%8s%s' % (log.COLOR_NONE, 
                                       str(c or '.'), 
                                       log.COLOR_NONE) 
                        for c in counters), 
              '\u2502 %d' % sum(counters))
    
    # also print severity totals
    if what != 'attributes':
        print('\u2500' * (param_max_len + 6 * 10) + '\u253c' + '\u2500' * 10)
        print('%s%-*s%s' % (log.COLOR_BLUE, param_max_len, 'TOTAL', log.COLOR_NONE), 
              '  '.join('%s%8s%s' % (log.COLOR_NONE, 
                                       str(st or '.'), 
                                       log.COLOR_NONE) 
                        for st in severity_totals), 
              '\u2502 %d' % sum(severity_totals))
        

def plot(events, display_filter_str): # TODO start, end
    display_filter = Filter.parse(display_filter_str)

    severities = ('UNKNOWN', 'none', 'info', 'notice', 'warning', 'critical')

    matches = display_filter.run() if display_filter else events.keys()
    if matches:
        log.info('Will plot %d events.' % len(matches))
    else:
        log.warn('No events match criteria.')
        return


    # TODO fix ticks
    #plt.style.use('dark_background')
    fig, ax = plt.subplots(1, 1, figsize=(8, 20))
    plt.xticks(rotation=30)
    by_severity = OrderedDict([(s, []) for s in severities])
    for db_id in matches or []:
        event = events[db_id]
        by_severity[event.severity].append(event.timestamp)

    ax.hist([mdates.date2num(by_severity[s]) for s in severities], 
            bins=50, stacked=True, 
            color=('darkgrey', 'lightgrey', 'yellowgreen', 'gold', 'orange', 'crimson'),
            label=severities)
    locator = mdates.AutoDateLocator()
    ax.xaxis.set_major_locator(locator)
    #ax.xaxis.set_major_locator(ticker.MultipleLocator(10))
    ax.xaxis.set_major_formatter(mdates.AutoDateFormatter(locator))
    handles, labels = ax.get_legend_handles_labels()
    plt.legend(handles[::-1], labels[::-1])
    plt.show()


def venn(events, *filters):
    if len(filters) > 6:
        log.err('Too many filters.')
        return

    filters = {f: Filter.parse(f) for f in filters}
    to_show = {f: set(e for e in events if F.test(e)) for f, F in filters.items()}
    venn_diagram(to_show)
    plt.show()


class Filter:
    debug_filter = False
    operators = {
        '==': 0.5,
        '!=': 0.5,
        '<': 0.5,
        '<=': 0.5,
        '>': 0.5,
        '>=': 0.5,
        'and': 0.2,
        'or': 0.1,
        'not': 0.3,
        'contains': 0.5,
        'matches': 0.5,
        'suspicious': 0.5,
        #'multior':, # TODO
    }
    
    def __init__(self, value, level, x1=None, x2=None):
        self.value = value
        self.level = level
        self.x1 = x1
        self.x2 = x2

    queries = {
        'timestamp': ("SELECT entry_id FROM Entry WHERE timestamp {} ?"),
        'source': ("SELECT E.entry_id "
                   "FROM Entry E INNER JOIN Source S "
                   "     ON E.source_id = S.source_id "
                   "WHERE S.path {} ?"),
        'category': ("SELECT E.entry_id "
                     "FROM Entry E INNER JOIN Category C "
                     "     ON E.category_id = C.category_id "
                     "WHERE C.name {} ?"),
        'score': ("SELECT entry_id FROM Entry WHERE score {} ?"),
        'severity': ("SELECT entry_id FROM Entry WHERE severity {} ?"),
        'message': ("SELECT entry_id FROM Entry WHERE message {} ?"),
        'attribute': ("SELECT DISTINCT(EA.entry_id) "
                      "FROM EA INNER JOIN Attribute A "
                      "        ON EA.attribute_id = A.attribute_id "
                      "WHERE A.name = ? AND EA.value {} ?"),
        'suspicious': ("SELECT DISTINCT(EA.entry_id) "
                       "FROM EA INNER JOIN Attribute A "
                       "        ON EA.attribute_id = A.attribute_id "
                       "WHERE A.name = ? AND EA.value IN (#)"),


    }
    def run(self):
        # comparison? return ids from select
        #print(self.x1, self.value, self.x2)
        #pdb.set_trace()
        try:
            if self.value in ('==', '!=', '<', '<=', '>', '>=', 'contains', 'matches'):
                to_replace = ('?', '?')
                operator = self.value
                # contains and matches are slightly different
                if self.value == 'contains':
                    to_replace = ('?', "'%' || ? || '%'")
                    operator = 'LIKE'
                if self.value == 'matches':
                    operator = 'REGEXP'

                if self.x1.value in ('timestamp', 'source', 'category', 'score', 'severity', 'message'):
                    # run non-attribute queries
                    return [x[0] for x in lib.db.query(lib.rreplace(Filter.queries[self.x1.value].format(operator), *to_replace, 1), (self.x2.value,))]
                else:
                    # attribute query
                    return [x[0] for x in lib.db.query(lib.rreplace(Filter.queries['attribute'].format(operator), *to_replace, 1), (self.x1.value, self.x2.value))]

            # suspicious? use WHERE IN query, return entry ids
            if self.value == 'suspicious':
                # get values
                suspects = Message.suspicious.get(self.x1.value)
                if not suspects:
                    return []
                # update placeholders in query, use suspects
                return [x[0] for x in lib.db.query(Filter.queries['suspicious'].replace('#', ','.join('?' for _ in suspects)), (self.x1.value, *suspects))]
                
            # boolean? return intersection/union of ids
            elif self.value == 'or':
                x1_result = self.x1.run()
                x2_result = self.x2.run()
                return list(set(x1_result + x2_result))
            elif self.value == 'and':
                x1_result = set(self.x1.run())
                x2_result = set(self.x2.run())
                return [x for x in x1_result if x in x2_result]
            elif self.value == 'not':
                x1_result = self.x1.run()
                all_entries = [x[0] for x in lib.db.query("SELECT entry_id FROM entry")]
                return list(set(all_entries) - set(x1_result))
        except:
            traceback.print_exc()
            log.err('Invalid filter.')
            return []
            
        
            
            

    def __str__(self):
        if self.x2:
            return '%s(%s, %s)' % (self.value, str(self.x1), str(self.x2))
        elif self.x1:
            return '%s(%s)' % (self.value, str(self.x1))
        else:
            return self.value

    def __repr__(self):
        return self.__str__()


    @staticmethod
    def parse(string):
        """
        x
        x == ?
        x != ?
        x < ?
        x <= ?
        x > ?
        x >= ?
        x and y
        x or y
        not x
        x contains ?
        x matches ?
        (x, y)
        ()
        " "
        ' '
        suspicious x

        x: timestamp, score, severity, source, category, message, <attr>
        """
        pattern = r'(".*?"|\'.*?\'|==|!=|<=|<|>=|>| or | and |not |\(|\)|contains|matches|suspicious|,)'
        parts = [x.strip() for x in re.split(pattern, string) if x.strip()]
        #print(parts)
        """ for each element compute its level """
        unique_levels = set()
        bracket_count = 0
        levels = []
        for part in parts:
            if bracket_count < 0:
                log.err('Bad bracket order!')
                break
            if part == '(':
                bracket_count += 1
                levels.append(-1)
            elif part == ')':
                bracket_count -= 1
                levels.append(-1)
            else:
                level = bracket_count + (Filter.operators.get(part) or 0.9)
                unique_levels.add(level)
                levels.append(level)
        
        #print('levels:', levels)
        #print('uniq levels:', unique_levels)
        if bracket_count:
            log.err('No matching brackets!')
        """ from topmost level, create objects and put them into a pool on same position """
        pool = [None for _ in parts]
        
        for level in sorted(unique_levels, reverse=True):
            if Filter.debug_filter:
                log.info('Looking for lvl %s elements' % level)
            leveled = [(parts[i], i) for i in range(len(parts)) if levels[i] == level]
            if Filter.debug_filter:
                log.info('  Matching leveled:', leveled)

            for part, i in leveled:
                """ convert to objects """
                operands = []

                if Filter.debug_filter:
                    log.info('    Dealing with "%s" at %d...' % (part, i))
                # collapse left of i if greater or equal level, skip None
                # same for right
                for direction, index_inc, border_cmp, level_cmp in [
                        ('left', -1, lambda x: x >= 0, lambda x, y: x >= y or x == -1), 
                        ('right', 1, lambda x: x < len(parts), lambda x, y: x > y or x == -1),
                    ]:
                    collapse_index = i
                    while True:
                        collapse_index += index_inc
                        if not border_cmp(collapse_index):
                            break
                        if level_cmp(levels[collapse_index], level):
                            if pool[collapse_index] is None: # already processed element
                                continue
                            if Filter.debug_filter:
                                log.info('      Collapsing %s...' % direction)
                            operands.append(pool[collapse_index]) # TODO continue with multior or what?
                            pool[collapse_index] = None
                            break
                        else:
                            break
                pool[i] = Filter(part, level, *operands)
                if Filter.debug_filter:
                    log.info('    new pool[%d]: %s' % (i, str(pool[i])))
        if Filter.debug_filter:
            log.info('pool at the end:', pool)

        """ only 1 should be left in the pool (or 0 if no filter) """
        remains = list(filter(None, pool))
        if len(remains) == 0:
            return None
        elif len(remains) == 1:
            return remains[0]
        else:
            log.err('Bad filter (not fully collapsed)!')
            return None



