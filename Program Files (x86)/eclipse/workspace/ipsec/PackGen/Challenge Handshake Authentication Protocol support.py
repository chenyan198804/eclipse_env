from scapy.all import *
import inspect

def lineno():
    """Returns the current line number in our program."""
    return inspect.currentframe().f_back.f_lineno
	
conf.iface = "eth1"

local_mac   = get_if_hwaddr(conf.iface)
remote_mac  = ""

ether = Ether(src=local_mac, dst="ff:ff:ff:ff:ff:ff")
host_uniq = "\x01\x02\x03\x04"

#ans = srp1(pppoe)

s = conf.L2socket(iface=conf.iface,filter="ether proto 0x8863 or ether proto 0x8864")

# padi = ether/PPPoED()/PPPoED_TagList()/PPPoED_Tag(type=0x0101)\
			# /PPPoED_Tag(type=0x0103, data=host_uniq)
#print padi.summary()
#s.send(padi)

while True:
	padi = s.recv()
	if padi is None:
		continue
	elif padi[PPPoED].code == 0x0009:
#		print bytes(pado).encode('hex')
		#print pado.summary()
		remote_mac  = padi[Ether].src
		#pppoed_tag = bytes(pado[PPPoED_TagList])
		
		pado = padi.copy();
		pado[Ether].dst = remote_mac
		pado[PPPoED].code = 0x0007
		pado[PPPoED_TagList].taglist = []
		
		tag_dict = {}
		tag_list = PPPoED_TagList()
		padi.show2()
		for tag in padi[PPPoED_TagList].taglist:
			if tag.type in [0x0103, 0x0101]:
				tag_list /= tag
				tag_dict[tag.type] = tag.data
		
		#print tag_dict
		#Host-Uniq tag is equal to PADI's Host-Uniq tag
		pado = Ether(src=local_mac, dst=remote_mac)\
				/PPPoED(code=0x0007)\
				/PPPoED_Tag(type=0x0101, data="\x41"*4)\
				/PPPoED_Tag(type=0x0102, data="\x42"*4)\
				/PPPoED_Tag(type=0x0103, data=tag_dict[0x0103])\
				/PPPoED_Tag(type=0x0104, data=RandString(4))
				#/PPPoED_Tag(type=0x0104, data="\x44"*4)
				
		#Host-Uniq tag is not equal to PADI's Host-Uniq tag
		# pado = Ether(src=local_mac, dst=remote_mac)\
				# /PPPoED(code=0x0007)\
				# /PPPoED_Tag(type=0x0101)\
				# /PPPoED_Tag(type=0x0102, data="\x42"*4)\
				# /PPPoED_Tag(type=0x0103, data="\x43"*4)\
				# /PPPoED_Tag(type=0x0104, data="\x44"*4)
		
		#no Host-Uniq tag
		# pado = Ether(src=local_mac, dst=remote_mac)\
				# /PPPoED(code=0x0007)\
				# /PPPoED_Tag(type=0x0101)\
				# /PPPoED_Tag(type=0x0102, data="\x42"*4)\
				# /PPPoED_Tag(type=0x0104, data="\x44"*4)
				
		#Host-Uniq tag is null
		# pado = Ether(src=local_mac, dst=remote_mac)\
				# /PPPoED(code=0x0007)\
				# /PPPoED_Tag(type=0x0101)\
				# /PPPoED_Tag(type=0x0102, data="\x42"*4)\
				# /PPPoED_Tag(type=0x0103)\
				# /PPPoED_Tag(type=0x0104, data="\x44"*4)
		s.send(pado)
		print "************send(pado)************"
		break
		
		# for i in range(1,3):
			# pado[Ether].src = RandMAC()
			# s.send(pado)
			# print "i= %d" % i
		# break;
# print "exit from line %s" % (lineno())
# exit()
#pppoe_sessionid = RandByte()
pppoe_sessionid = 0x0010

while True:
	padr = s.recv()
	if padr is None:
		continue		   
	elif padr[PPPoED].code == 0x0019:
		tag_list = PPPoED_TagList()
		tag_dict = {}
		for tag in padi[PPPoED_TagList].taglist:
			if tag.type in [0x0103]:
				tag_list /= tag
				tag_dict[tag.type] = tag.data
				break
				
		#Host-Uniq tag is not equal to PADR's Host-Uniq tag
		pads = Ether(src=local_mac, dst=remote_mac)\
				/PPPoED(code=0x0065, sessionid=pppoe_sessionid)\
				/PPPoED_Tag(type=0x0101)\
				/PPPoED_Tag(type=0x0103, data=tag_dict[0x0103])

		#Host-Uniq tag is not equal to PADR's Host-Uniq tag
		# pads = Ether(src=local_mac, dst=remote_mac)\
				# /PPPoED(code=0x0065, sessionid=pppoe_sessionid)\
				# /PPPoED_Tag(type=0x0101)\
				# /PPPoED_Tag(type=0x0103, data="\x43"*4)
		
		#no Host-Uniq tag
		# pads = Ether(src=local_mac, dst=remote_mac)\
				# /PPPoED(code=0x0065, sessionid=pppoe_sessionid)\
				# /PPPoED_Tag(type=0x0101)

		#Host-Uniq tag is null
		# pads = Ether(src=local_mac, dst=remote_mac)\
				# /PPPoED(code=0x0065, sessionid=pppoe_sessionid)\
				# /PPPoED_Tag(type=0x0101)\
				# /PPPoED_Tag(type=0x0103)
				
		s.send(pads)
		print "************send(pads)************"
		break

#magic_number = "\x41"*4
magic_number = ''.join(RandString(4))			#if directly assign RandString(4) to magic_number, the value of magic_number will change everytime
send_lcp_request_flag = True
send_ipcp_request_flag = True
send_chap_challenge_flag = True


while True:
	ppp = s.recv()
	#print bytes(ppp).encode('hex')
	if ppp is None or ppp[Ether].src == local_mac:			#bypass the packet from local
		continue
	elif ppp[Ether].type == 0x8863 and ppp[PPPoED].code == 0xa7:
		print "***************receive PADT*********************"
		exit()
	elif ppp[Ether].type == 0x8864:
		if ppp[PPP].proto == 0xc021 and send_lcp_request_flag:
			# ppp_lcp_request = ppp.copy()
			# ppp_lcp_request[Ether].src = local_mac
			# ppp_lcp_request[Ether].dst = remote_mac
			
			##config magic_number
			# for i in ppp_lcp_request[PPP_LCP].options:
				# print i.data.encode('hex')
				# if i.type == 0x05:
					# i.data = magic_number
					# break;
					
			# print "**************ppp_lcp_request***************"
			# ppp_lcp_request.show2()
			# print "**************ppp_lcp_request***************"
			ppp_lcp_request = Ether(src=local_mac, dst=remote_mac)\
					/PPPoE(code=0x00, sessionid=pppoe_sessionid)\
					/PPP()\
					/PPP_LCP(code=0x01)
			ppp_lcp_request.options = PPP_LCP_Option(type=0x05, data=magic_number)\
					/PPP_LCP_Option(type=0x03, data="\xc2\x23\x05")		#c023 is pap, c223 is chap
			s.send(ppp_lcp_request)

			# ppp_lcp_request.options = PPP_LCP_Option(type=0x05, data=magic_number)
			# s.send(ppp_lcp_request)
			
			# Verify Other PPP LCP Option
			# for i in PPP_LCP_Options_Types.keys():
				# ppp_lcp_request.options = PPP_LCP_Option(type=i, data=RandString(2))
				# s.send(ppp_lcp_request)
			send_lcp_request_flag = False
			
		if ppp[PPP].proto == 0xc021:		#PPP LCP Protocol
			if ppp[PPP_LCP].code in [1]: 	#PPP LCP Request
	#			ppp.show2()
	#			print "-----------------"
				ppp_lcp_reply = ppp
				ppp_lcp_reply[Ether].src = local_mac
				ppp_lcp_reply[Ether].dst = remote_mac
				ppp_lcp_reply[PPP_LCP].code = 2
				s.send(ppp_lcp_reply)
				
			elif ppp[PPP_LCP].code in [9]: #receive ppp lcp echo request
				ppp_lcp_reply = ppp
				ppp_lcp_reply[Ether].src = local_mac
				ppp_lcp_reply[Ether].dst = remote_mac
				ppp_lcp_reply[PPP_LCP].code = 10
				ppp_lcp_reply[PPP_LCP].options = magic_number
	#			ppp_lcp_reply.show2()
				s.send(ppp_lcp_reply)
				
				ppp_lcp_echo_request = ppp
				ppp_lcp_echo_request[Ether].src = local_mac
				ppp_lcp_echo_request[Ether].dst = remote_mac
				ppp_lcp_echo_request[PPP_LCP].code = 0x09
				ppp_lcp_echo_request[PPP_LCP].options = magic_number
				s.send(ppp_lcp_echo_request)
			  
				# ppp_lcp_termination_request = ppp
				# ppp_lcp_termination_request[Ether].src = local_mac
				# ppp_lcp_termination_request[Ether].dst = remote_mac
				# ppp_lcp_termination_request[PPP_LCP].code = 0x05
				# ppp_lcp_termination_request[PPP_LCP].options = "Peer not responding"
				# s.send(ppp_lcp_termination_request)
				
				# ppp_pap = Ether()/PPPoE()/PPP()/PPP_PAP()
				# ppp_pap[Ether].src =local_mac
				# ppp_pap[Ether].dst = remote_mac
				# ppp_pap[PPPoE].sessionid = ppp[PPPoE].sessionid
				# ppp_pap[PPP].proto = 0xc023
				# ppp_pap[PPP_PAP].code = 0x01
				# ppp_pap[PPP_PAP].data = PPP_PAP_Data(data="rp-pppoe")/PPP_PAP_Data(data="rp-pppoe")
				#ppp_pap.show2()
				# s.send(ppp_pap)
				if send_chap_challenge_flag:
					ppp_chap_challenge = Ether()/PPPoE()/PPP()/PPP_CHAP()
					ppp_chap_challenge[Ether].src =local_mac
					ppp_chap_challenge[Ether].dst = remote_mac
					ppp_chap_challenge[PPPoE].sessionid = ppp[PPPoE].sessionid
					ppp_chap_challenge[PPP].proto = 0xc223
					ppp_chap_challenge[PPP_CHAP].code = 0x01
					ppp_chap_challenge[PPP_CHAP].data = PPP_CHAP_Data(data=RandString(24), name="A"*63)
					#ppp_chap_challenge.show2()
					s.send(ppp_chap_challenge)
					send_chap_challenge_flag = False
					# print "exit from line %s" % (lineno())
					# exit()
			
		elif ppp[PPP].proto == 0xc223 and ppp[PPP].code in [2]:			#receive PPP CHAP Response
			ppp_chap_challenge = Ether()/PPPoE()/PPP()/PPP_CHAP()
			ppp_chap_challenge[Ether].src =local_mac
			ppp_chap_challenge[Ether].dst = remote_mac
			ppp_chap_challenge[PPPoE].sessionid = ppp[PPPoE].sessionid
			ppp_chap_challenge[PPP].proto = 0xc223
			ppp_chap_challenge[PPP_CHAP].code = 0x04
			ppp_chap_challenge[PPP_CHAP].data = "Authentication Failed"
			s.send(ppp_chap_challenge)
			exit()
			# None

		elif ppp[PPP].proto == 0xc023 and ppp[PPP].code in [1]:			#PPP PAP Request
#			ppp_pap_reply = Ether(src=local_mac, dst=remote_mac)\
#					  /PPPoE(sessionid=pppoe_sessionid)\
#					  /PPP(proto=0xc023)\
#					  /PPP_PAP(id=1)\
#					  /PPP_PAP_Data(data="rp-pppoe")/PPP_PAP_Data(data="rp-pppoe")
			# ppp_pap_reply = ppp
			# ppp_pap_reply[Ether].src =local_mac
			# ppp_pap_reply[Ether].dst = remote_mac
			# ppp_pap_reply[PPP_PAP].code = 0x02
			#ppp_pap_reply[PPP_PAP].len = 13
			# ppp_pap_reply[PPP_PAP].data = PPP_PAP_Data(data="Login OK")
			##ppp_pap.show2()
			# s.send(ppp_pap_reply)
			
			ppp_pap_reply = Ether()/PPPoE()/PPP()/PPP_PAP()
			ppp_pap_reply[Ether].src =local_mac
			ppp_pap_reply[Ether].dst = remote_mac
			ppp_pap_reply[PPPoE].sessionid = ppp[PPPoE].sessionid
			ppp_pap_reply[PPP_PAP].code = 0x02
			ppp_pap_reply[PPP_PAP].data = PPP_PAP_Data(data="Login OK")
			s.send(ppp_pap_reply)
			
			ppp_ipcp_request = Ether()/PPPoE()/PPP()/PPP_IPCP()
			ppp_ipcp_request[Ether].src =local_mac
			ppp_ipcp_request[Ether].dst = remote_mac
			ppp_ipcp_request[PPPoE].sessionid = ppp[PPPoE].sessionid
			ppp_ipcp_request[PPP].proto = 0x8021
			ppp_ipcp_request[PPP_IPCP].id = 0x01
			ppp_ipcp_request[PPP_IPCP].options = PPP_IPCP_Option_IPAddress(data="10.0.0.1")
			# ppp_ipcp_request[PPP_IPCP].options = PPP_IPCP_Option_IPAddress(data=RandIP())
			#ppp_ipcp_request[PPP_IPCP].options = PPP_IPCP_Option_IPAddress(data="11.0.0.3")
			# print "*********************ppp_ipcp_request.show2()*********************"
			# ppp_ipcp_request.show2()
			# print hexdump(ppp_ipcp_request)
			# print "*********************ppp_ipcp_request.show2()*********************"
			s.send(ppp_ipcp_request)

		elif ppp[PPP].proto == 0x8021:
			if ppp[PPP_IPCP].code in [1]:				#ppp ipcp request
				ppp_ipcp_reply = ppp.copy();
				ppp_ipcp_reply[Ether].src =local_mac
				ppp_ipcp_reply[Ether].dst = remote_mac
				
				if send_ipcp_request_flag:
					ppp_ipcp_request = Ether()/PPPoE()/PPP()/PPP_IPCP()
					ppp_ipcp_request[Ether].src =local_mac
					ppp_ipcp_request[Ether].dst = remote_mac
					ppp_ipcp_request[PPPoE].sessionid = ppp[PPPoE].sessionid
					ppp_ipcp_request[PPP].proto = 0x8021
					ppp_ipcp_request[PPP_IPCP].id = 0x01
					ppp_ipcp_request[PPP_IPCP].options = PPP_IPCP_Option_IPAddress(data="10.0.0.1")
					s.send(ppp_ipcp_request)
					send_ipcp_request_flag = False
					
				for ipcp_option in ppp[PPP_IPCP].options:
					if type(ipcp_option) is PPP_IPCP_Option_IPAddress:
						hexdump(ipcp_option)
						if ipcp_option.data == "0.0.0.0":
							ppp_ipcp_reply[PPP_IPCP].code = 0x03
							ppp_ipcp_reply[PPP_IPCP_Option_IPAddress].data = "10.0.0.2"
							s.send(ppp_ipcp_reply)
						else:
							ppp_ipcp_reply[PPP_IPCP].code = 0x02
							s.send(ppp_ipcp_reply)
				
							# ppp_ipcp_termination_request = Ether()/PPPoE()/PPP()/PPP_IPCP()
							# ppp_ipcp_termination_request[Ether].src =local_mac
							# ppp_ipcp_termination_request[Ether].dst = remote_mac
							# ppp_ipcp_termination_request[PPPoE].sessionid = ppp[PPPoE].sessionid
							# ppp_ipcp_termination_request[PPP].proto = ppp[PPP].proto
							# ppp_ipcp_termination_request[PPP_IPCP].id = ppp[PPP_IPCP].id
							# ppp_ipcp_termination_request[PPP_IPCP].code = 0x05
							# s.send(ppp_ipcp_termination_request)
							# print "exit from line %s" % (lineno())
							# exit()

			elif ppp[PPP_IPCP].code in [2]:
				#send ppp ipcp termination request
				None
				# break;
			elif ppp[PPP_IPCP].code in [3]:
				ppp_ipcp = ppp;
				ppp_ipcp[Ether].src =local_mac
				ppp_ipcp[Ether].dst = remote_mac
				ppp_ipcp[PPP_IPCP].code = 0x01
				s.send(ppp_ipcp)
s.close()