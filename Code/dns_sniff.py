#!/usr/bin/env python

from scapy.all import *
from datetime import datetime
import time
import datetime
import sys

interface = 'wlp2s0'
filter_bpf = 'udp and port 53'

def select_DNS(pkt):
   
            print(pkt.show())
 
# ------ START SNIFFER 
sniff(iface=interface, filter=filter_bpf, store=0,  prn=select_DNS)