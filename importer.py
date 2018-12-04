# -*- coding: utf-8 -*-
#! /usr/bin/env python3

from sys import argv
from re import compile, VERBOSE
from signature import Signature


REGEX = compile(r""" ^
    #sID
    (\d{,99999}:\s)?
    #PROTO
    ([A-Z]{,4}\s)
    #IP
    (!?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:)|any:)
    #PORT
    (!?[0-9]{,6}\s|(any)\s|!?\[[0-9]{,6}-[0-9]{,6}\]\s)
    #DIR
    (<>\s|->\s)
    #IP
    (!?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:)|any:)
    #PORT
    (!?[0-9]{,6}\s|(any)\s|!?\[[0-9]{,6}-[0-9]{,6}\]\s)
    #PAYLOAD TODO
    (\*)
        $ """, VERBOSE)
try:
    RULEPATH = argv[2]
except IndexError:
    RULEPATH = 'eval.rules'
finally:
    print('[*] loading %s' % RULEPATH)


def verify_rules(ruleset):
    signatures = []
    for rule in ruleset:
        if rule[0] != '#':
            if REGEX.match(rule):
                sig = Signature(rule)
                if sig.sID == '':
                    sig.sID = str(len(signatures)+1)
                if sig.sID in [s.sID for s in signatures]:
                    raise ValueError(' ID in use for %s' % (rule))
                signatures.append(sig)
            else:
                raise ValueError(' %s does not match the syntax' %(rule))
    try:
        signatures[0]
    except IndexError as e:
        raise ValueError('empty signature set')
    else:
        return signatures


def loadRules(path):
    try:
        with open(path) as new_file:
            rules = new_file.readlines()
    except FileNotFoundError as e:
        raise ValueError(e)
    else:
        try:
            vrules = verify_rules([x.strip() for x in rules if len(x)>1])
        except ValueError as e:
            raise e
        else:
            return vrules

try:
    RULES = loadRules(RULEPATH)
    print('[*] parsed rules')
except ValueError as e:
    exit('[@]'+str(e))
