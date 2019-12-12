# -*- coding: utf-8 -*-
#! /usr/bin/env python3

from sys import argv
from re import compile as reg_comp, VERBOSE
from signature import Signature


REGEX = reg_comp(r""" ^
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
    #PAYLOAD
    (\*)
        $ """, VERBOSE)
try:
    RULEPATH = argv[2]
except IndexError:
    RULEPATH = 'eval.rules'
finally:
    print(f"[*] loading {RULEPATH}")


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
                raise ValueError(f"{rule} does not match the syntax")
    try:
        signatures[0]
    except IndexError:
        raise ValueError('empty signature set')
    else:
        return signatures


def load_rules(path):
    try:
        with open(path) as new_file:
            rules = new_file.readlines()
    except FileNotFoundError as err:
        raise ValueError(err)
    else:
        try:
            vrules = verify_rules([x.strip() for x in rules if len(x) > 1])
        except ValueError as err:
            raise err
        else:
            return vrules

try:
    RULES = load_rules(RULEPATH)
    print('[*] parsed rules')
except ValueError as err:
    exit(f"[@] {err}")
