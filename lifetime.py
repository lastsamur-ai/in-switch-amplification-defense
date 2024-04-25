#!/usr/bin/env python3
from scapy.all import Ether,ICMP,IP,TCP,srp1,sniff,sendp
import os

traffic=sniff(offline="/home/user/Workspace/forwarding/Normal_Group/Normal_1/Normal-h3_1.pcap",filter="ip dst host 192.168.20.133")

for pkt in traffic:
	pkt.getlayer(IP).src='10.0.2.2'
	pkt.getlayer(IP).dst='10.0.1.1'
	pkt.src='00:00:0a:00:02:02'
	pkt.dst='00:00:0a:00:01:01'
	pkt.sport=4567
	pkt.dport=80


'''SCENARIO
send 50 normal packets
shoot 2 crystals
send another 40 normal packets
shoot 3 crystals
send 10 normal packets
shoot 10 crystals
send 300 normal packets
should total to about 556 packets
'''
normal=[50,50,10,50]
crystals=[1,1,1]

traffic_index=0
for i,j in zip(normal,crystals):
	sendp(traffic[traffic_index:i+traffic_index],iface='h2-eth0')
	traffic_index=traffic_index+i
	os.system("./ufonet/ufonet -a 'http:10.0.1.1' --tachyon '{}' &".format(j))
