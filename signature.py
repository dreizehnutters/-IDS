# -*- coding: utf-8 -*-
#! /usr/bin/env python3

from helper import switch_directions, not_eq
from scapy.all import Ether, IP, IPv6, ARP, ICMP

class Signature(object):
    def __init__(self, obj, with_payload=False):
        super(Signature, self).__init__()
        if isinstance(obj, Ether):
            direction = '->'
            sID = '-1'
            if IP in obj:
                try:
                    proto = obj[2].name
                    srcIP = str(obj[1].src)
                    srcPort = str(obj[1].sport)
                    dstIP = str(obj[1].dst)
                    dstPort = str(obj[1].dport)
                    payload = '*'
                except AttributeError:
                    if ICMP in obj:
                        proto = obj[2].name
                        srcIP = str(obj[1].src)
                        srcPort = 'any'
                        dstIP = str(obj[1].dst)
                        dstPort = 'any'
                        payload = '*'
                    else:
                        raise ValueError()
                except IndexError:
                    raise ValueError()
            else:
                raise ValueError()
        elif isinstance(obj, str):
            string = obj.split(' ')
            if len(string) == 5:
                s2 = string[1].split(':')
                s4 = string[3].split(':')

                sID = ''
                proto = string[0]
                srcIP = s2[0]
                srcPort = s2[1]
                direction = string[2]
                dstIP = s4[0]
                dstPort = s4[1]
                payload = string[4]
                
            elif len(string) == 6:
                s2 = string[2].split(':')
                s4 = string[4].split(':')

                sID = string[0].split(':')[0]
                proto = string[1]
                srcIP = s2[0]
                srcPort = s2[1]
                direction = string[3]
                dstIP = s4[0]
                dstPort = s4[1]
                payload = string[5]
        else:
            raise ValueError(obj, 'cant be initialized')
        del obj
        self.sID = sID
        self.proto = proto
        self.srcIP = srcIP
        self.srcPort = srcPort
        self.dir = direction
        self.dstIP = dstIP
        self.dstPort = dstPort
        self.payload = payload

    def __str__(self):
        return '%s %s:%s %s %s:%s %s' % (self.proto, self.srcIP, self.srcPort, self.dir,\
                                         self.dstIP, self.dstPort, self.payload)
    def __repr__(self):
        return 'rule %s: %s' %( self.sID, self.__str__())

    def __eq__(self, other):
        """
        nicht kommutativ
        self immer ohne !/any/<>/portRange
        """
        if isinstance(self, other.__class__):

            if other.dir == '<>':
                a, b = switch_directions(other)
                return self.__eq__(a) or self.__eq__(b)

            # proto
            if other.proto != 'any':
                if not_eq(other.proto, self.proto):
                    return False

            # srcIP
            if other.srcIP != 'any':
                if not_eq(other.srcIP, self.srcIP):
                    return False

            # srcPort
            if other.srcPort != 'any':
                if not_eq( other.srcPort, self.srcPort, 0):
                    return False

            # dstIP
            if other.dstIP != 'any':
                if not_eq(other.dstIP, self.dstIP):
                    return False

            # dstPort
            if other.dstPort != 'any':
                if not_eq(other.dstPort, self.dstPort, 0):
                    return False

            # payload
            if other.payload != 'any':
                if self.payload != other.payload:
                    return False

            return True
        else:
            return False
