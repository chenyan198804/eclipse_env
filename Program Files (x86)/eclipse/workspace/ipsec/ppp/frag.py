from scapy.all import *

#conf.iface = "eth0"

a = fragment(IP(dst="10.69.194.1")/ICMP()/("a"*1000),fragsize=100)
b = fragment(IP(dst="10.69.194.1")/UDP()/("x"*1000),fragsize=100)
c = fragment(IP(dst="10.69.194.1")/TCP()/("x"*1000),fragsize=100)

for i in range(0, len(a)):
	send(a[i])
	send(b[i])
	# send(c[i])