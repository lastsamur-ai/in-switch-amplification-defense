#!/usr/bin/env python3
from scapy.all import *
import os
import sys

if len(sys.argv)<2:
	print("Please specify round (0-3).")
	exit()

p = int(sys.argv[1])

normal=[50,50,10,50]
crystals=[1,1,1]
#should amount to a total of 290 packets (128 normal, 162 recon or amplification)

if p ==0:
	r=0
	print("Round 0: sending {} normal packets via h2-eth0".format(normal[r]))
elif p ==1:
	r=1
	print("Round 1: sending {} normal packets via h2-eth0".format(normal[r]))
elif p==2:
	r=2
	print("Round 2: sending {} normal packets via h2-eth0".format(normal[r]))
elif p==3:
	r=3
	print("Round 3: sending {} normal packets via h2-eth0".format(normal[r]))
else:
	print("Please specify round (1-4).")
	exit()

traffic=sniff(offline="/home/user/Workspace/forwarding/Normal_Group/Normal_1/Normal-h3_1.pcap",filter="ip dst host 192.168.20.133")

for pkt in traffic:
	pkt.getlayer(IP).src='10.0.2.2'
	pkt.getlayer(IP).dst='10.0.1.1'
	pkt.src='00:00:0a:00:02:02'
	pkt.dst='00:00:0a:00:01:01'
	pkt.sport=4567
	pkt.dport=80

import time
traffic_index=100

for a in range(r):
	traffic_index=traffic_index+normal[a]

for i in range(traffic_index,normal[r]+traffic_index,1):
	print('sending packet # {} of length {}'.format(i,len(traffic[i])))
	time.sleep(1)
	sendp(traffic[i],iface='h2-eth0')
#sendp(traffic[traffic_index:normal[r]+traffic_index],iface='h2-eth0')
