#!/usr/bin/python3

import os
import sys

if os.getuid() !=0:
    print('ERROR: This script requires root privileges. Use sudo to run it.')
    quit()

from scapy.all import *


# Send to highspeed; all packets should be fragmented successfully.
for i in range(11):
     b = 'H'*200
     p = (Ether()/IP(src='10.11.12.13', dst='192.168.5.2')/TCP(sport=7,dport=7)/b)
     sendp(p, iface='veth0')
     input('send next pkts: (enter to continue)')


# # a real_net pkt
# # Ethernet 14B, IP 20B, TCP 20B: does not match 88-byte fragmentation,
# # so it generates two identical packets, one with DUMMY_CHECKSUM.
# b = bytes([i for i in range(10)])
# p = (Ether()/IP(src='10.0.0.1', dst='10.0.0.2')/TCP(sport=7,dport=7)/b)
# sendp(p, iface='veth2')



# pkts=rdpcap('obf.pcap')  # could be used like this rdpcap('filename',500) fetches first 500 pkts
# for pkt in pkts:
#      sendp(pkt, iface='veth22') #sending packet at layer 2
#      input('send next pkts: (enter to continue)')

