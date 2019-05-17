#!/usr/bin/env python3
"""
General-purpose stuff is defined here.
"""
import re
import signal
import sys
from source import log
from dateutil.parser import parse as dateutil_parse
from tzlocal import get_localzone
from datetime import datetime

def positive(x):
    if type(x) == str:
        x = x.lower()
    if x in ['yes', 'y', '+', '1', 1, 'true', 't', True]:
        return True
    return False

def negative(x):
    if type(x) == str:
        x = x.lower()
    if x in ['no', 'n', '-', '0', 0, 'false', 'f', False]:
        return True
    return False

def quit_string(x):
    if type(x) != str:
        return False
    x = x.lower()
    if x in ['quit', 'exit', 'q', 'end', ':wq']:
        return True
    return False

def exit_program(signal, frame):
    """immediate termination due to -h, bad parameter or bind() fail"""
    if signal == -1:                 
        sys.exit(0)

    log.newline() # newline
    #log.info('Killing all the threads...')
    sys.exit(0 if signal is None else 1)

# run exit program on SIGINT
signal.signal(signal.SIGINT, exit_program)

def chunks(data, size):
    for i in range(0, len(data), size):
        yield data[i:i+size]

def normalize_datetime(time=None):
    if not time:
        return datetime.now().astimezone(get_localzone())
    if type(time) == str:
        variant = 0
        while True:
            try:
                return dateutil_parse(time).astimezone(get_localzone())
            except ValueError:
                variant += 1
                if variant == 1: # apache-access format
                    time = time.replace(':', ' ', 1)
                else:
                    log.err('  Cannot unify datetime:', time)
                    return None
    elif type(time) == datetime:
        return time.astimzeone(get_localzone())
    elif type(time) in (int, float):
        # probably UNIX timestamp
        return datetime.utcfromtimestamp(time).astimezone(get_localzone())
    else:
        log.err('  Unknown time type:', time, type(time))
        return None


def natural_sort(data):
    return sorted(data, key=lambda x: [int(s) if s.isdigit() else s 
                                       for s in re.split(r'(\d+)', str(x))])

def find_between(data, startbytes, endbytes, startpos=0, endpos=0, inner=False):
    """
    This function goes through data[startpos:endpos] and locates 
    substrings 'startbytes.*endbytes'.
    
    inner specifies whether startbytes and endbytes should be 
    included in match_string.

    Returns:
        list of (absolute_position, match_string)
    """
    if endpos == 0:
        endpos = len(data)
    result = []
    while True:
        try:
            """set up start, find end from it"""
            offset = data.index(startbytes, startpos)
            start = offset+(len(startbytes) if inner else 0)
            end = data.index(endbytes, start)+(0 if inner else len(endbytes))
            if end>endpos:
                """stop if outside the scope"""
                break
            result.append((offset, data[start:end]))
            """prepare for next search"""
            startpos = end
        except ValueError: # out of bounds (no more matches)?
            break
    return result


def split_escaped(string, delimiter):
    if len(delimiter) != 1:
        raise ValueError('Invalid delimiter: ' + delimiter)
    ln = len(string)
    i = 0
    j = 0
    while j < ln:
        if string[j] == '\\':
            if j + 1 >= ln:
                yield string[i:j].replace('\\', '')
                return
            j += 1
        elif string[j] == delimiter:
            yield string[i:j].replace('\\', '')
            i = j + 1
        j += 1
    yield string[i:j].replace('\\', '')

chunks = lambda data,size: [data[x:x+size] for x in range(0, len(data), size)]

def get_colored_printable(b):
    """

    """
    color = log.COLOR_BROWN
    if b in (0x9, 0xa, 0xd):
        color = log.COLOR_DARK_GREEN
        b = ord('.')
    elif b<0x20 or b>=0x7f:
        color = log.COLOR_NONE
        b = ord('.')
    return color+chr(b)+log.COLOR_NONE

def get_colored_printable_hex(b):
    """

    """
    color = log.COLOR_NONE
    if b>=0x20 and b<0x7f:
        color = log.COLOR_BROWN
    elif b in (0x9, 0xa, 0xd):
        color = log.COLOR_DARK_GREEN
    return color + '%02x' % b + log.COLOR_NONE

def hexdump(data):
    """
    Prints data as with `hexdump -C` command.
    """
    result = []
    line_count = 0
    for chunk in chunks(data, 16):
        hexa = ' '.join(''.join(get_colored_printable_hex(b) for b in byte) 
                        for byte in [chunk[start:start+2] 
                                     for start in range(0, 16, 2)])
        
        """add none with coloring - for layout"""
        if len(hexa)<199:
            hexa += (log.COLOR_NONE+'  '+log.COLOR_NONE)*(16-len(chunk))

        result.append(log.COLOR_DARK_GREEN 
                      + '%08x' % (line_count*16) 
                      + log.COLOR_NONE 
                      + '  %-160s' % (hexa) 
                      + ' |' 
                      + ''.join(get_colored_printable(b) for b in chunk) + '|')
        line_count += 1
    return result


def run_command(command):
    """
    Run command in shell.

    Args:
        command (str) - command to execute

    Returns:
        return code
        standard output
        standard error output
    """
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    (out, err) = p.communicate()
    return (p.returncode, out, err)

def diff_lines(lines_1, lines_2, form='D'):
    """
    Diffs 2 sets of lines. 

    Args:
        lines_1 (list of str): first sample
        lines_2 (list of str): second sample
        form (str): diff form to perform
                    D - full diff (default)
                    1 - only lines unique to first set
                    2 - only lines unique to second set
                    c - only common lines
                    d - only different lines
    """
    lines = [line for line in difflib.Differ().compare(lines_1, lines_2)
             if not line.startswith('?')]
    """alert with respect to form"""
    if form == '1':
        lines = [line[2:] for line in lines if line.startswith('-')]
    elif form == '2':
        lines = [line[2:] for line in lines if line.startswith('+')]
    elif form == 'c':
        lines = [line[2:] for line in lines 
                      if not line.startswith(('-', '+'))]
    elif form == 'd':
        lines = [line for line in lines 
                      if line.startswith(('-', '+'))]
    return lines	

severity_colors = {
    'critical': log.COLOR_RED,
    'warning': log.COLOR_BROWN,
    'notice': log.COLOR_YELLOW,
    'info': log.COLOR_DARK_GREEN,
    'none': log.COLOR_GREY,
    'UNKNOWN': log.COLOR_DARK_GREY,
}

# --

