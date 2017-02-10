from scapy.all import *

#this is a little helper script to spoof IPv6 router advertisements
#to inform honeyd about the default router

a = IPv6()
a.dst = "2001:638:807:3b::b0"
a.src = "2001:638:807:3b::1"

b = ICMPv6ND_RA()

c = ICMPv6NDOptSrcLLAddr()
c.lladdr = "00:23:04:51:b6:40"

d = ICMPv6NDOptMTU()

e = ICMPv6NDOptPrefixInfo()
e.prefixlen = 64
e.prefix = "2001:638:807:3b::"

sendp(Ether()/a/b/c/d/e,iface="eth1")

