from scapy.all import *

conf.iface = "eth0"

# build_lfilter = lambda (r): r[Ether].dst == get_if_hwaddr("eth0"))
# sniff(iface="eth0", prn = lambda x: x.summary(), filter="icmp")

#def chgSend(x):
#    x[IP].dst = '192.168.1.1'
#    send(x)
#while 1:
#    sniff(prn=chgSend, filter="host 10.69.196.91")

icmp = IP(src=get_if_addr("eth0"), dst="10.69.196.1")/ICMP()
send(icmp)
sniff(prn=lambda x:x.summary(), iface="eth0", filter="icmp", store=0, timeout=2)

#padi=Ether(src=get_if_hwaddr("eth0"),dst="ff:ff:ff:ff:ff:ff")\
#        /PPPoED()/PPPoED_TagList()/PPPoED_Tag(tag_type=0x0101)\
#        /PPPoED_Tag(tag_type=0x0103,tag_value="\x01\x02")
#        
#sendp(padi)
#
#sniff(prn=lambda x:x.summary(), iface="eth0", filter="ether proto 0x8863", store=0)
