# The Unmasking of Joker: In-switch DNS Amplification Defense

```
                   +--+
                   |h4|
                   ++-+
                    |
                    |
+--+      +--+     ++-+     +--+
|h1+------+s1+-----+s3+-----+h3|
+--+      +-++     +--+     +--+
            |
            |
          +-++
          |s2|
          +-++
            |
            |
          +-++
          |h2|
          +--+
```

## Introduction

We launch a DNS amplification attack in the test enviroment. We use mininet and Scapy to regenerate normal traffic from InSDN. Test enviroment includes hosts h1, h2, h3, and h4 that represent
the victim machine, attacker, DNS server, and zombie (compromised machine), respectively. All machines are accessible across the network over links that connect (h1,s1), (s1,s2), (h2,s2), (h3,s3),
and (h4,s3). The victim machine runs a web service on port 80. DNS server runs dnsmasq (DNS service) and the compromised machine exposes a vulnerable Open Redirect service. Adversary sends normal and malicious traffic towards the victim, DNS server, and the compromised server.

## Network Setup

Run the topology:
```bash
./network
```

```bash
h1> python3 -m http.server 80
h3> dnsmasq --log-queries --no-daemon
h4> python3 redirect.py
h2> python3 send_normal.py 0
h2> python3 ./ufonet./ufonet -a "http://10.0.1.1" --tachyon "1"
h2> python3 send_normal.py 1
```

## Pre-requisites
Install P4 as specified in Dr. Vanbever's course on <a href="https://github.com/nsg-ethz/p4-learning">Advanced Topics in Networking</a><br>
Create a /presence directory<br>
Download InSDN/Normal_Group/Normal_1/Normal-h3_1.pcap<br>
Install UFOnet and its dependencies.<br>

UFOnet incorporates hard-coded snippets. Follow these steps to work around this:<br>

most likely, UFOnet TACHYON module is not going to be able to open this dns file.<br>
go to ufonet/core/mods/tachyon.py<br>
go to line 32:<br>
comment out open file block and add your list of dns servers like below:<br>
        #with open(dns_file) as f: # extract OpenDNS servers from file<br>
            #dns_d = f.read().splitlines() <br>
        #f.close()<br>
        dns_d=['10.0.3.3']<br>

go to ufonet/core/main.py<br>
add this code after line 101 (replace directory with working directory)<br>
self.wwa = '/home/user/Desktop/forwarding/ufonet/'#where we are with the installation<br>
        l=['mothershipname']<br>
        for v in self.__dict__:<br>
            if 'file' in v or v in l:<br>
                self.__dict__[v]=self.wwa+self.__dict__[v]<br>
go to ufonet/core/options.py<br>
add this code after line 26<br>
self.wwa = '/home/user/Desktop/forwarding/ufonet/'#where we at with the installation<br>
        for v in self.__dict__:<br>
            if 'file' in v or v in l:<br>
                self.__dict__[v]=self.wwa+self.__dict__[v]<br>
also go to main.py about line 352 and change those lines to the following<br>
self.wwa = '/home/user/Workspace/forwarding/ufonet/'<br>
if not os.path.exists(self.wwa+"core/json/"): # create gui json cfg files folder<br>
    os.mkdir(self.wwa+"core/json/")<br>
