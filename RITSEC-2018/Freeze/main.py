# uncompyle6 version 3.2.4
# Python bytecode 2.7 (62211)
# Decompiled from: Python 2.7.15+ (default, Aug 31 2018, 11:56:52) 
# [GCC 8.2.0]
# Embedded file name: main.py
# Compiled at: 2018-02-03 10:56:33
import datetime, struct
str = '\\x6a\\x71\\x61\\x62\\x7d\\x7a\\x4d\\x47\\x5f\\x55\\x59\\x5b\\x6e\\x4f\\x51\\x53\\x42\\x55\\x67\\x51\\x46\\x6e\\x55\\x40\\x69\\x43\\x45\\x48\\x5d\\x47\\x6e\\x4b\\x4c\\x5f\\x44\\x4d'

def a():
    time_res = datetime.datetime(1998, 1, 19, 0, 0).strftime('%s')
    time_now = datetime.datetime.now().strftime('%s')
    if time_now == time_res:
        print '\nHappy Birthday Hulto! :) \nHere is your flag:'
        b(time_res, str)
        print '\n'


def b(key, flag):
    res = ''
    arr = flag.split('\\x')[1:]
    for i in range(0, len(arr)):
        res += chr(ord(key[i % len(key)]) ^ int(arr[i], 16))

    print res


a()
print datetime.datetime.now().strftime('%s')
# okay decompiling main_out.pyc
