#! /usr/bin/env python3

import hashlib
import os.path
import sys

import ID2TLib.libpcapreader as pr
import time

def merge():
    #base = ['/root/datasets/201506021400_2G.pcap', '/root/datasets/201506021400_5G.pcap', '/root/datasets/201506021400.pcap']
    base = ['/root/datasets/201506021400.pcap']
    attack = ['/root/attack_pcaps/portscan_ddos_attack.pcap']
    #attack = ['/root/attack_pcaps/portscan_attack.pcap', '/root/attack_pcaps/ddos_attack.pcap']
    
    for b in base:
        print("processing ", b)
        pcap = pr.pcap_processor(b)
        start = time.time()
        for a in attack:
            print("injecting attack: " + a + " at " + str(time.time()))
            dest_path = pcap.merge_pcaps(a)
        end = time.time()
        f = open('/root/perfresults/runtime_mergeop.txt', 'a')
        f.write(b + ':  ' + str(end-start) + '\n')
        f.close()

merge()
