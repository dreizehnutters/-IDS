# -*- coding: utf-8 -*-
#! /usr/bin/env python3

from re import findall
from copy import deepcopy


def not_eq(o, s, normal=True):
    if normal:
        if o == 'IP' and s in ['TCP','UDP']:
            return False
        else:    
            return s == o[1:] if o[0] == '!' else s != o
    else:
        if s == 'any':
            return False
        split = o.split('!')
        if '-' in o:
            sp = split[-1].split('-')
            min_ = sp[0][1:]
            max_ = sp[1][:-1]
        else:
            min_ = split[-1]
            max_ = split[-1]

        o = range(int(min_), int(max_)+1)
        try:
            s = int(s)
        except ValueError as e:
            print('no meaning full compare/TODO:', s)
            return True
        else:
            return (len(split) == 1 and s not in o) or\
                   (len(split) == 2 and s in o)


def switch_directions(signatur):

    srcdst = deepcopy(signatur)
    srcdst.dir = '->'

    dstsrc = deepcopy(signatur)
    dstsrc.dir = '->'
    dstsrc.srcIP = dstsrc.dstIP
    dstsrc.srcPort = dstsrc.dstPort
    dstsrc.dstIP = srcdst.srcIP
    dstsrc.dstPort = srcdst.srcPort

    return srcdst, dstsrc


def num_of_layers(packet):
    return len(findall('[|]', packet.__repr__()))
