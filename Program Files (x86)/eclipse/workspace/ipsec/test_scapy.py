from scapy.all import *

conf.iface = 'eth1'

sniff(filter = "udp port 500", timeout = 30,  prn = lambda x: x.summary())