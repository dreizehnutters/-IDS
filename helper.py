# -*- coding: utf-8 -*-
#! /usr/bin/env python3

from re import findall
from copy import deepcopy


def not_eq(other_, self_, normal=True):
    if normal:
        if other_ == 'IP' and self_ in ['TCP', 'UDP']:
            return False
        else:
            return self_ == other_[1:] if other_[0] == '!' else self_ != other_
    else:
        if self_ == 'any':
            return False
        split = other_.split('!')
        if '-' in other_:
            split_split = split[-1].split('-')
            min_ = split_split[0][1:]
            max_ = split_split[1][:-1]
        else:
            min_ = split[-1]
            max_ = split[-1]

        other_ = range(int(min_), int(max_)+1)
        try:
            self_ = int(self_)
        except ValueError:
            print(f"no meaning full compare/TODO: {self_}")
            return True
        else:
            return (len(split) == 1 and self_ not in other_) or\
                   (len(split) == 2 and self_ in other_)


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
