# -*- coding: utf-8 -*-
#! /usr/bin/env python3
from os import makedirs, path
from sys import argv
from time import sleep, time
from multiprocessing import Queue
from sniffer import Sniffer
from analyzer import Analyzer

print('\n\
 █████╗  ██████╗███████╗██╗         ██╗██████╗ ███████╗\n\
██╔══██╗██╔════╝██╔════╝██║         ██║██╔══██╗██╔════╝\n\
███████║██║     ███████╗██║         ██║██║  ██║███████╗\n\
██╔══██║██║     ╚════██║██║         ██║██║  ██║╚════██║\n\
██║  ██║╚██████╗███████║███████╗    ██║██████╔╝███████║\n\
╚═╝  ╚═╝ ╚═════╝╚══════╝╚══════╝    ╚═╝╚═════╝ ╚══════╝')


if __name__ == '__main__':
    try:
        INTERFACE = argv[1]
    except IndexError:
        exit("[@] no interface was passed (main.py <INTERFACE>)")
    else:
        if not path.exists('logs'):
            makedirs('logs')
    finally:
        QUEUE = Queue()
        TIMESTAMP = str(time()).split('.')[0]
        LOG_FILE = open('logs/'+TIMESTAMP+".log", "w")
        SNIFFER = Sniffer(INTERFACE, QUEUE, TIMESTAMP)
        ANALYZER = Analyzer(QUEUE, LOG_FILE)

    try:
        print('[*] start sniffing')
        SNIFFER.start()
        print('[*] start analyzing')
        ANALYZER.start()
        while True:
            sleep(100)
    except KeyboardInterrupt:
        print('[*] stopping IDS')
        LOG_FILE.close()
        ANALYZER.join()
        sleep(.1)
        SNIFFER.join()
        print('[*] bye')
