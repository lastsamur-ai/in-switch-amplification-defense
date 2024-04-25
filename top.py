from p4utils.mininetlib.net import Mininet
#from p4utils.mininetlib.net import P4Mininet
from p4utils.mininetlib.network_API import NetworkAPI
from mininet.net import *
from p4utils.mininetlib.node import *

net = NetworkAPI()
natIP = '10.0.3.3'
# Network general options
net.setLogLevel('info')
net.enableCli()

# Network definition
net.addP4Switch('s1', cli_input='s1-commands.txt')
net.setThriftPort('s1', 9091)
net.addP4Switch('s2', cli_input='s2-commands.txt')
net.setThriftPort('s2', 9092)
net.addP4Switch('s3', cli_input='s3-commands.txt')
net.setThriftPort('s3', 9093)
net.setP4SourceAll('forwarding.p4')

net.addHost('h1')
net.addHost('h2')
net.addHost('h3')
net.addHost('h4')

net.addLink('h1','s1')
net.addLink('h2','s2')
net.addLink('s1','s2')
net.addLink('s1','s3')
net.addLink('h3','s3')
net.addLink('h4','s3')


#nat0 = net.addNAT("nat0" , connect = None , inNamespace = False , ip = natIP )
#net.addLink( nat0 , 's6')
#add NAT/internet/DNS connectivity
#net.addNAT().configDefault()

# Assignment strategy
net.mixed()

# Nodes general options
net.enablePcapDumpAll()
net.enableLogAll()

net.startNetwork()
