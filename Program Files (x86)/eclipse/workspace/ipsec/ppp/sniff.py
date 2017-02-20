from scapy.all import *
from threading import Thread

conf.iface = "eth0"

local_mac   = get_if_hwaddr(conf.iface)
remote_mac  = ""

ether = Ether(src=local_mac, dst="ff:ff:ff:ff:ff:ff")
host_uniq = "\x01\x02\x03\x04"

#ans = srp1(pppoe)


class SnifferThread(Thread):
    def __init__ (self,filter="ether proto 0x8863"):
        Thread.__init__(self)
        self.filter = filter
    def run(self):
        sniff(filter=self.filter, prn=self.pkt_callback, store=0, timeout=0.2)
    def pkt_callback(self,pkt):
        remote_mac  = pkt[Ether].dst
        if pkt[PPPoED].code == 0x0007:
            #print 7
            #tag = pkt[PPPoED_Tag]
                #print tag.encode('hex')
            #print pkt.summary()

if __name__ == '__main__':
    sniffer = SnifferThread("ether proto 0x8863")
    sniffer.start()
    padi = ether/PPPoED()/PPPoED_TagList()/PPPoED_Tag(tag_type=0x0101)\
            /PPPoED_Tag(tag_type=0x0103, tag_value=host_uniq)
    sendp(padi)
    sniffer = SnifferThread()
    sniffer.start()
    #sniffer.join() 

    #print ans.summary()
    #sniff(prn=lambda x: x.summary(), filter="ether proto 0x8863", timeout=10)