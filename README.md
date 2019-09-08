# DHCP_spoofing_attack
This is an implementation of DHCP spoofing attack for CSE 406 security lab. The design and final report contains detailed description of the attack and its implementation.

##  Tools

Python

Scapy (2.3.3)


## Setup

> make sure python and scapy is installed, also install wireshark for seeing a detailed info of the packets

> run DHCPstarve.py

> run DHCPSpoof.py

> run dns_sniff.py

Note: If the client or mobile device is already connected to the network this won't work since the router already has a saved IP for your device. 
ALWAYS PERFORM FORGET NETWORK BEFORE RUNNING


##  Resources :

DHCP protocol : 

> http://www.networksorcery.com/enp/protocol/dhcp.htm

> https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol

> https://learningnetwork.cisco.com/docs/DOC-24355

DHCP message format : 

> http://www.omnisecu.com/tcpip/dhcp-dynamic-host-configuration-protocol-message-format.php

https://www.whitewinterwolf.com/posts/2017/10/30/dhcp-exploitation-guide/

subnets and IP addresses : 

> https://routersecurity.org/ipaddresses.php#targetText=A%20common%20IP%20address%20is,is%20visible%20on%20the%20Internet.

DHCP Starvation : 

> https://www.youtube.com/watch?v=7RJ1Pn4Fl9Q&t=106s
> https://github.com/shreyasdamle/DHCP-Starvation-/blob/master/dhcp_starvation.py
> https://github.com/avaiyang/dhcp-starvation-attack/blob/master/dhcp_starve.py


** DHCP Spoof : 
> https://github.com/byt3bl33d3r/DHCPShock/blob/master/dhcpshock.py
> https://support.huawei.com/enterprise/en/doc/EDOC1100058937/40d3ec1/man-in-the-middle-attack-ip-mac-spoofing-attack-and-dhcp-exhaustion-attack

Scapy cheatsheet :

> https://blogs.sans.org/pen-testing/files/2016/04/ScapyCheatSheet_v0.2.pdf

Scapy documentation : 
> https://buildmedia.readthedocs.org/media/pdf/scapy/latest/scapy.pdf

Python Docs : 

> https://docs.python.org/2/library/argparse.html

Scapy listener in python : 

> https://jcutrer.com/python/scapy-dhcp-listener

Packet sniffer : 

> https://medium.com/@777rip777/packet-sniffer-with-scapy-part-3-a895ce7e9cb

DHCP snooping : https://orhanergun.net/2017/03/layer-2-security-dhcp-details-dhcp-snooping/
http://www.firewall.cx/cisco-technical-knowledgebase/cisco-switches/1215-understanding-dhcp-snooping-concepts-and-how-it-works.html

DHCP spoof using Mininet : https://github.com/floft/dhcp-spoof

MITM : https://seclists.org/vuln-dev/2002/Sep/99

https://security.stackexchange.com/questions/172687/what-is-the-role-of-arp-poisoning-when-doing-a-dhcp-spoofing-attack?newreg=05b564b9b8374bb7af97e9917fc967bc

Others

> https://stackoverflow.com/questions/44937242/how-to-determine-if-an-ip-packet-is-dhcp-packet

> https://stackoverflow.com/questions/50026438/crafting-a-dhcp-offer-packet-in-scapy

> https://stackoverflow.com/questions/22720788/dhcp-release-using-scapy

> https://stackoverflow.com/questions/57811366/continue-net-connection-of-victim-after-dhcp-spoofing-attack

> https://medium.com/@lucideus/dhcp-starvation-attack-with-dhcp-rogue-server-lucideus-research-68b2447de7d0

Preventing DHCP starvation in real world : 
> http://www.revolutionwifi.net/revolutionwifi/2011/03/preventing-dhcp-starvation-attacks.html

> https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3560/software/release/12-2_44_se/configuration/guide/scg/swdhcp82.html#wp1078853
