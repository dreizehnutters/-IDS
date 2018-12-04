# -*- coding: utf-8 -*-
#! /usr/bin/env python3

from multiprocessing import Process, Event
from scapy.all import Ether
from signature import Signature
from importer import RULES


class Analyzer(Process):
    def __init__(self, task_queue, file):
        super(Analyzer, self).__init__()
        self.daemon = True
        self.stop = Event()
        self.task_queue = task_queue
        self.file  = file
        self.with_pNUM = False

    def isDead(self):
        return self.stop.is_set()

    def isIntrusion(self, packet, index):
        summary = packet.summary()
        try:
            packet_signature = Signature(packet)
        except ValueError as e:
            print('[@]', e, summary)
        else:
            for offset, rule in enumerate(RULES):
                if packet_signature == rule:
                    msg = '%s ~> %s' %(RULES[offset].__repr__(), summary) 
                    print('[!!] '+msg)
                    if self.with_pNUM:
                        msg = ('p%s %s' % (str(index), msg))
                    self.file.write(msg+'\n')
                    self.file.flush()
                    return True
            print('[=]', summary)
            return False

    def run(self):
        index = 1
        while not self.isDead():
            self.isIntrusion(Ether(self.task_queue.get()), index)
            index += 1

    def join(self, timeout=None):
        self.stop.set()
        super().join(timeout)
