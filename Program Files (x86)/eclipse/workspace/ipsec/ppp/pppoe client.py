from scapy.all import *

conf.iface = "eth0"

local_mac   = get_if_hwaddr(conf.iface)
remote_mac  = ""

ether = Ether(src=local_mac, dst="ff:ff:ff:ff:ff:ff")
host_uniq = "\x01\x02\x03\x04"

#ans = srp1(pppoe)

s = conf.L2socket(iface="eth0",filter="ether proto 0x8863 or ether proto 0x8864")

padi = ether/PPPoED()/PPPoED_TagList()/PPPoED_Tag(type=0x0101)\
			/PPPoED_Tag(type=0x0103, data=host_uniq)

#print padi.summary()

s.send(padi)
#for i in range(1,5):
#	pado = s.recv()
#	print pado.summary()

while True:
	pado = s.recv()
	if pado is None:
		continue
	
	elif pado[PPPoED].code == 0x0007:
#		print bytes(pado).encode('hex')
		#print pado.summary()
		remote_mac  = pado[Ether].src
		pppoed_tag = bytes(pado[PPPoED_TagList])
		break;


ether.dst = remote_mac
padr = Ether(src=local_mac, dst=remote_mac)/PPPoED(code=0x19)/pppoed_tag
pppoe_sessionid = 0x00
#padr.show2()	
s.send(padr)

while True:
	pads = s.recv()
	if pads is None:
		continue		   
		
	elif pads[PPPoED].code == 0x0065:
		pppoe_sessionid = pads[PPPoED].sessionid
		break

magic_number = "\x41\x41\x41\x41\x41"
send_lcp_request_flag = True

while True:
	ppp_lcp = s.recv()
	#print bytes(ppp_lcp).encode('hex')
	if ppp_lcp is None or ppp_lcp[Ether].src == local_mac:			#bypass the packet from local
		continue  
	elif ppp_lcp[Ether].type == 0x8864:
		if ppp_lcp[PPP].proto == 0xc021 and send_lcp_request_flag:
			ppp_lcp_request = ppp_lcp.copy()
			ppp_lcp_request[Ether].src = local_mac
			ppp_lcp_request[Ether].dst = remote_mac
			
			#config magic_number
			for i in ppp_lcp_request[PPP_LCP].options:
				print i.data.encode('hex')
				if i.type == 0x05:
					i.data = magic_number
					break;
					
			print "**************ppp_lcp_request***************"
			ppp_lcp_request.show2()
			print "**************ppp_lcp_request***************"
			
			s.send(ppp_lcp_request)
			send_lcp_request_flag = False
			
		if ppp_lcp[PPP].proto == 0xc021:		#PPP LCP Protocol
			if ppp_lcp[PPP_LCP].code in [1]: 	#PPP LCP Request
	#			ppp_lcp.show2()
	#			print "-----------------"
				 
				ppp_lcp_reply = ppp_lcp
				ppp_lcp_reply[Ether].src = local_mac
				ppp_lcp_reply[Ether].dst = remote_mac
				ppp_lcp_reply[PPP_LCP].code = 2
				s.send(ppp_lcp_reply)
				
			elif ppp_lcp[PPP_LCP].code in [9]: #receive ppp lcp echo request
				ppp_lcp_reply = ppp_lcp
				ppp_lcp_reply[Ether].src = local_mac
				ppp_lcp_reply[Ether].dst = remote_mac
				ppp_lcp_reply[PPP_LCP].code = 10
	#			ppp_lcp_reply.show2()
				s.send(ppp_lcp_reply)
				
				ppp_lcp_echo_request = ppp_lcp
				ppp_lcp_echo_request[Ether].src = local_mac
				ppp_lcp_echo_request[Ether].dst = remote_mac
				ppp_lcp_echo_request[PPP_LCP].code = 9
				ppp_lcp_echo_request[PPP_LCP].options = magic_number
				s.send(ppp_lcp_echo_request)
			  
				ppp_pap = Ether()/PPPoE()/PPP()/PPP_PAP()
				ppp_pap[Ether].src =local_mac
				ppp_pap[Ether].dst = remote_mac
				ppp_pap[PPPoE].sessionid = ppp_lcp[PPPoE].sessionid
				ppp_pap[PPP].proto = 0xc023
				ppp_pap[PPP_PAP].code = 0x01
				ppp_pap[PPP_PAP].data = PPP_PAP_Data(data="rp-pppoe")/PPP_PAP_Data(data="rp-pppoe")
				#ppp_pap.show2()
				s.send(ppp_pap)
			
		elif ppp_lcp[PPP].proto == 0xc023 and ppp_lcp[PPP].code in [1]:			#PPP PAP protocol
#			ppp_pap = Ether(src=local_mac, dst=remote_mac)\
#					  /PPPoE(sessionid=pppoe_sessionid)\
#					  /PPP(proto=0xc023)\
#					  /PPP_PAP(id=1)\
#					  /PPP_PAP_Data(data="rp-pppoe")/PPP_PAP_Data(data="rp-pppoe")
			ppp_pap = ppp_lcp;
			ppp_pap[Ether].src =local_mac
			ppp_pap[Ether].dst = remote_mac
			ppp_pap[PPP_PAP].code = 0x02
			ppp_pap[PPP_PAP].data = PPP_PAP_Data(data="Login OK")
#			ppp_pap.show2()
			s.send(ppp_pap)
			
			ppp_ipcp_request = Ether()/PPPoE()/PPP()/PPP_IPCP()
			ppp_ipcp_request[Ether].src =local_mac
			ppp_ipcp_request[Ether].dst = remote_mac
			ppp_ipcp_request[PPPoE].sessionid = ppp_lcp[PPPoE].sessionid
			ppp_ipcp_request[PPP].proto = 0x8021
			ppp_ipcp_request[PPP_IPCP].id = 0x01
			ppp_ipcp_request[PPP_IPCP].options = PPP_IPCP_Option_IPAddress(data="11.0.0.3")
			print "*********************ppp_ipcp_request.show2()*********************"
			#ppp_ipcp_request.show2()
			print hexdump(ppp_ipcp_request)
			print "*********************ppp_ipcp_request.show2()*********************"
			s.send(ppp_ipcp_request)

		elif ppp_lcp[PPP].proto == 0x8021:
			if ppp_lcp[PPP_IPCP].code in [1]:
				ppp_ipcp = ppp_lcp;
				ppp_ipcp[Ether].src =local_mac
				ppp_ipcp[Ether].dst = remote_mac
				ppp_ipcp[PPP_IPCP].code = 0x02
				s.send(ppp_ipcp)
			elif ppp_lcp[PPP_IPCP].code in [2]:
				#None
				break;
			elif ppp_lcp[PPP_IPCP].code in [3]:
				ppp_ipcp = ppp_lcp;
				ppp_ipcp[Ether].src =local_mac
				ppp_ipcp[Ether].dst = remote_mac
				ppp_ipcp[PPP_IPCP].code = 0x01
				s.send(ppp_ipcp)
s.close()