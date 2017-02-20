from scapy.all import *

conf.iface = "eth0"

local_mac   = get_if_hwaddr(conf.iface)
remote_mac  = ""

ether = Ether(src=local_mac, dst="ff:ff:ff:ff:ff:ff")
host_uniq = "\x01\x02\x03\x04"

#ans = srp1(pppoe)

s = conf.L2socket(iface="eth0",filter="ether proto 0x8863 or ether proto 0x8864")

padi = ether/PPPoED()/PPPoED_TagList()/PPPoED_Tag(tag_type=0x0101)\
            /PPPoED_Tag(tag_type=0x0103, tag_value=host_uniq)

#print padi.summary()

s.send(padi)
#for i in range(1,5):
#    pado = s.recv()
#    print pado.summary()

while True:
    pado = s.recv()
    if pado is None:
        continue
    
    elif pado[PPPoED].code == 0x0007:
#        print bytes(pado).encode('hex')
        #print pado.summary()
        remote_mac  = pado[Ether].src
        
        #print remote_mac
        #print 7
        #print str(pkt[PPPoED_TagList]).encode('hex')
        pppoed_tag = bytes(pado[PPPoED_TagList])
        
        i = 0
        tag_type=[]
        tag_len=[]
        tag_value=[]
        
    #            while i < len(pppoed_tag):
        while i < pado[PPPoED].len:
            tag_type.append(int(pppoed_tag[i:i+2].encode('hex'), 16))
            tag_len.append(int(pppoed_tag[i+2:i+4].encode('hex'), 16))
            tag_value.append(pppoed_tag[i+4:i+4+tag_len[-1]])
            i  += (4 + tag_len[-1])
            
#            print hex(tag_type[-1])
#            print hex(tag_len[-1])
#            print tag_value[-1].encode('hex')
        
        break;


ether.dst = remote_mac
padr = Ether(src=local_mac, dst=remote_mac)/PPPoED(code=0x19)/pppoed_tag
#padr.show2()    
s.send(padr)

while True:
    pads = s.recv()
    if pads is None:
        continue           
        
    elif pads[PPPoED].code == 0x0065:
        pppoed_tag = bytes(pads[PPPoED_TagList])
#            print "--------------------"
#            print pppoed_tag.encode('hex')
#            print "--------------------"
        
        i = 0
        tag_type=[]
        tag_len=[]
        tag_value=[]
        
        #print pkt[PPPoED].len
#            while i < len(pppoed_tag):        Why not use len(pppoed_tag), becasuse it's passible that the pppoed pacekts is less than 64, then padding
        while i < pads[PPPoED].len:
            tag_type.append(int(pppoed_tag[i:i+2].encode('hex'), 16))
            tag_len.append(int(pppoed_tag[i+2:i+4].encode('hex'), 16))
            tag_value.append(pppoed_tag[i+4:i+4+tag_len[-1]])
            
            i  += (4 + tag_len[-1])
            
#            print hex(tag_type[-1])
#            print hex(tag_len[-1])
#            print tag_value[-1].encode('hex')
            
        break

while True:
    ppp_lcp = s.recv()
    #print bytes(ppp_lcp).encode('hex')
    if ppp_lcp is None:
        continue  
    elif ppp_lcp[Ether].type == 0x8864:
        ppp_lcp_request = ppp_lcp.copy()
        ppp_lcp_request[Ether].src = local_mac
        ppp_lcp_request[Ether].dst = remote_mac
        ppp_lcp_request.payload.load = ppp_lcp_request.payload.load[:len(ppp_lcp_request.payload.load)-4]+"aaaa"
        ppp_lcp_request.show2()
        s.send(ppp_lcp_request)
        
        ppp_lcp[Ether].src = local_mac
        ppp_lcp[Ether].dst = remote_mac
        ppp_lcp.payload.load = "\x02" + ppp_lcp.payload.load[1:]
        ppp_lcp.show2()
        s.send(ppp_lcp)
        
        #print ppp_lcp_len
        
        ppp_lcp_option_type=[]
        ppp_lcp_option_len=[]
        ppp_lcp_option_value=[]
        ppp_lcp_options = {}
        
        
#        ppp_lcp_code        = int(ppp_lcp.payload.load[0:1].encode('hex'), 16)
#        ppp_lcp_identifier  = int(ppp_lcp.payload.load[1:2].encode('hex'), 16)
#        ppp_lcp_len         = int(ppp_lcp.payload.load[2:4].encode('hex'), 16)

        ppp_lcp_code        = ppp_lcp.payload.load[0:1]
        ppp_lcp_identifier  = ppp_lcp.payload.load[1:2]
        ppp_lcp_len         = ppp_lcp.payload.load[2:4]
        
#        print bytes(ppp_lcp.payload.load).encode('hex')
#        print ppp_lcp_len.encode('hex')
        
        ppp_lcp.payload.load = ppp_lcp.payload.load[4:]
        #print pkt[PPPoED].len
#            while i < len(pppoed_tag):        Why not use len(pppoed_tag), becasuse it's passible that the pppoed pacekts is less than 64, then padding
        i = 0
        while i < int(ppp_lcp_len.encode('hex'),16):
#            type = int(ppp_lcp.payload.load[i:i+1].encode('hex'), 16)
#            len  = int(ppp_lcp.payload.load[i+1:i+2].encode('hex'), 16)
            type = ppp_lcp.payload.load[i:i+1]
            len  = ppp_lcp.payload.load[i+1:i+2]
            value= ppp_lcp.payload.load[i+2:i+int(len.encode('hex'), 16)]
#            print type.encode('hex')
#            print len.encode('hex')
#            print value.encode('hex')
            i += (int(len.encode('hex'), 16)+2)                #ppp_lcp_len contain length of (type and len)
            ppp_lcp_options[type] = [len, value]
            #break
            
#        print ppp_lcp_options
#            ppp_lcp_option_type.append(int(ppp_lcp.payload.load[i:i+1].encode('hex'), 16))
#            ppp_lcp_option_len.append(int(ppp_lcp.payload.load[i+1:i+2].encode('hex'), 16))
#            ppp_lcp_option_value.append(ppp_lcp.payload.load[i+2:i+ppp_lcp_option_len[-1]])           
#            i  += (ppp_lcp_option_len[-1])


#        ether.src = local_mac
#        ether.dst = remote_mac
#        ether.type= 0x8864
#        payload = ppp_lcp[Ether].payload.copy()
#        #ppp_lcp_ack = ether()/(bytes(ppp_lcp[Ether].payload))
#        ppp_lcp_ack = ether()/payload
#        ppp_lcp_ack.payload.load = "\x02" + ppp_lcp_ack.payload.load[1:]
#        
#        print "-----------------ppp_lcp_ack----------------------"
#        ppp_lcp_ack.show2()
#        print "-----------------ppp_lcp_ack----------------------"
#        s.send(ppp_lcp_ack)
        
        #ppp_lcp.show2()
        #s.send(ppp_lcp)
        break;
    
s.close()

