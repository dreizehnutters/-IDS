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
        self.file = file
        self.with_packer_num = False

    def is_dead(self):
        return self.stop.is_set()

    def is_intrusion(self, packet, index):
        summary = packet.summary()
        try:
            packet_signature = Signature(packet)
        except ValueError as err:
            print(f"[@] {err} {summary}")
        else:
            for offset, rule in enumerate(RULES):
                if packet_signature == rule:
                    msg = f"{RULES[offset].__repr__()} ~> {summary}"
                    print(f"[!!] {msg}")
                    if self.with_packer_num:
                        msg = (f"p{index} {msg}")
                    self.file.write(msg+'\n')
                    self.file.flush()
                    return True
            print(f"[=] {summary}")
            return False

    def run(self):
        index = 1
        while not self.is_dead():
            self.is_intrusion(Ether(self.task_queue.get()), index)
            index += 1

    def join(self, timeout=None):
        self.stop.set()
        super().join(timeout)
