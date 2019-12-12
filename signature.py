# -*- coding: utf-8 -*-
#! /usr/bin/env python3

from scapy.all import Ether, IP, ICMP
from helper import switch_directions, not_eq

class Signature(object):
    """Signature"""
    def __init__(self, obj):
        super(Signature, self).__init__()
        if isinstance(obj, Ether):
            direction = '->'
            s_id = '-1'
            if IP in obj:
                try:
                    proto = obj[2].name
                    src_ip = str(obj[1].src)
                    src_port = str(obj[1].sport)
                    dst_ip = str(obj[1].dst)
                    dst_port = str(obj[1].dport)
                    payload = '*'
                except AttributeError:
                    if ICMP in obj:
                        proto = obj[2].name
                        src_ip = str(obj[1].src)
                        src_port = 'any'
                        dst_ip = str(obj[1].dst)
                        dst_port = 'any'
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
                src_split = string[1].split(':')
                dst_split = string[3].split(':')

                s_id = ''
                proto = string[0]
                src_ip = src_split[0]
                src_port = src_split[1]
                direction = string[2]
                dst_ip = dst_split[0]
                dst_port = dst_split[1]
                payload = string[4]

            elif len(string) == 6:
                src_split = string[2].split(':')
                dst_split = string[4].split(':')

                s_id = string[0].split(':')[0]
                proto = string[1]
                src_ip = src_split[0]
                src_port = src_split[1]
                direction = string[3]
                dst_ip = dst_split[0]
                dst_port = dst_split[1]
                payload = string[5]
        else:
            raise ValueError(obj, 'cant be initialized')
        del obj
        self.s_id = s_id
        self.proto = proto
        self.src_ip = src_ip
        self.src_port = src_port
        self.dir = direction
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.payload = payload

    def __str__(self):
        return f"{self.proto} {self.src_ip}:{self.src_port} {self.dir} \
                              {self.dst_ip}:{self.dst_port} {self.payload}"
    def __repr__(self):
        return f"rule {self.s_id}: {self.__str__()}"

    def __eq__(self, other):
        """
        nicht kommutativ
        self immer ohne !/any/<>/portRange
        """
        if isinstance(self, other.__class__):

            if other.dir == '<>':
                dir_a, dir_b = switch_directions(other)
                return self.__eq__(dir_a) or self.__eq__(dir_b)

            # proto
            if other.proto != 'any':
                if not_eq(other.proto, self.proto):
                    return False

            # src_ip
            if other.src_ip != 'any':
                if not_eq(other.src_ip, self.src_ip):
                    return False

            # src_port
            if other.src_port != 'any':
                if not_eq(other.src_port, self.src_port, 0):
                    return False

            # dst_ip
            if other.dst_ip != 'any':
                if not_eq(other.dst_ip, self.dst_ip):
                    return False

            # dst_port
            if other.dst_port != 'any':
                if not_eq(other.dst_port, self.dst_port, 0):
                    return False

            # payload
            if other.payload != 'any':
                if self.payload != other.payload:
                    return False

            return True
        else:
            return False
