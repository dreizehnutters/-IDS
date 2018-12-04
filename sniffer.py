# -*- coding: utf-8 -*-
#! /usr/bin/env python3

from multiprocessing import Process, Event
from scapy.all import conf, sniff, wrpcap, ETH_P_ALL


class Sniffer(Process):
    def __init__(self, interface, queue, name):
        super(Sniffer, self).__init__()
        self.daemon = True
        self.socket = None
        self.interface = interface
        self.stop = Event()
        self.que = queue
        self.logName = name
        
    def run(self):
        self.socket = conf.L2listen(type=ETH_P_ALL, iface=self.interface)
        packets = sniff(opened_socket=self.socket,
                        prn=self.analyze_packet,
                        stop_filter=self.stop_sniffering)
        wrpcap('logs/'+self.logName+'.pcap', packets)

    def analyze_packet(self, packet):
        self.que.put(bytes(packet))

    def stop_sniffering(self, packet):
        return self.stop.is_set()
    
    def join(self, timeout=None):
        self.stop.set()
        super().join(timeout)
