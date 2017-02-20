#! /usr/bin/env python
#############################################################################
##                                                                         ##
## This script is used to test IKEv2, it only support 3DES-CBC and SHA1-96 ##
## The difficulty is calculate keys                                        ##
##                                                                         ##
## Copyright (C) 2012  wukun  <wukun0451@gmail.com>                        ##
##                                                                         ##
##                                                                         ##
##                                                                         ##
## This program is free software; you can redistribute it and/or modify it ##
## under the terms of the GNU General Public License version 2 as          ##
## published by the Free Software Foundation; version 2.                   ##
##                                                                         ##
## This program is distributed in the hope that it will be useful, but     ##
## WITHOUT ANY WARRANTY; without even the implied warranty of              ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       ##
## General Public License for more details.                                ##
##                                                                         ##
#############################################################################

####### History ############################################################
## wukun @03/31/2012: 
##          - add response to Ctrl+C keyboard. When press Ctrl+C, the script
##            will send PADT.
## wukun @@2012-09-15: 
##          - draft this script

from scapy.all import *
import inspect
import signal
import time

interrupted = False

def signal_handler(signum, frame):
    global interrupted
    interrupted = True

signal.signal(signal.SIGINT, signal_handler)

def lineno():
    """Returns the current line number in our program."""
    return inspect.currentframe().f_back.f_lineno

#select the right interface, you can use command "get_if_list()", "get_if_hwaddr('eth0')", "get_if_addr('eth0')" to lookup interface
conf.iface = "eth1"

#get local interface's mac address
local_mac   = get_if_hwaddr(conf.iface)
remote_mac  = ""

ether = Ether(src=local_mac, dst="ff:ff:ff:ff:ff:ff")

'''PPPoED Tag
0x0000: 'End-Of-List',
0x0101: 'Service-Name',
0x0102: 'AC-Name',
0x0103: 'Host-Uniq',
0x0104: 'AC-Cookie',
0x0105: 'Vendor-Specific',
0x0110: 'Relay-Session-Id',
0x0201: 'Service-Name-Error',
0x0202: 'AC-System-Error',
0x0203: 'Generic-Error'
'''
service_name = "aaaaa"
ac_name = "bbbbbb"
host_uniq = ''.join(RandString(4))
ac_cookie = ''.join(RandString(4))

#configure L2socket, we will use this socket to send and receive packet
#and we only note PPPoED and PPPoE packet
s = conf.L2socket(iface=conf.iface,filter="ether proto 0x8863 or ether proto 0x8864")

while True:
	padi = s.recv()
	#pass None packet and packet send from local
	if padi is None or padi[Ether].src == local_mac:        #padi.haslayer[PPPoED]
		continue
	#receive padi packet
	elif padi[PPPoED].code == 0x09:
#		print bytes(pado).encode('hex')
		#print pado.summary()
		remote_mac  = padi[Ether].src
		#pppoed_tag = bytes(pado[PPPoED_TagList])
		
		pado = padi.copy();
		pado[Ether].dst = remote_mac
		pado[PPPoED].code = 0x07
		pado[PPPoED_TagList].taglist = []
		
		tag_dict = {}
		tag_list = PPPoED_TagList()
		padi.show2()
		#get host_uniq from padi packet
		for tag in padi[PPPoED_TagList].taglist:
			if tag.type in [0x0103]:
				tag_list /= tag
				tag_dict[tag.type] = tag.data
				break
		
		pado = Ether(src=local_mac, dst=remote_mac)\
				/PPPoED(code=0x07)\
				/PPPoED_Tag(type=0x0101, data = service_name)\
				/PPPoED_Tag(type=0x0102, data = ac_name)\
				/PPPoED_Tag(type=0x0103, data = tag_dict[0x0103])\
				/PPPoED_Tag(type=0x0104, data = ac_cookie)

		s.send(pado)
		print "************send(pado)************"
		break

#pppoe_sessionid = RandByte()
pppoe_sessionid = 0x0010

while True:
	padr = s.recv()
	if padr is None or padr[Ether].src == local_mac:
		continue		   
	elif padr[PPPoED].code == 0x19:
		tag_list = PPPoED_TagList()
		tag_dict = {}
		for tag in padi[PPPoED_TagList].taglist:
			if tag.type in [0x0103]:
				tag_list /= tag
				tag_dict[tag.type] = tag.data
				break

		pads = Ether(src=local_mac, dst=remote_mac)\
				/PPPoED(code=0x65, sessionid=pppoe_sessionid)\
				/PPPoED_Tag(type=0x0101, data = service_name)\
				/PPPoED_Tag(type=0x0103, data=tag_dict[0x0103])

				
		s.send(pads)
		print "************send(pads)************"
		break

#magic_number = "\x41"*4
magic_number = ''.join(RandString(4))			#if directly assign RandString(4) to magic_number, the value of magic_number will change everytime
send_lcp_request_flag = True
send_lcp_other_request_flag = True
send_ipcp_request_flag = True
send_chap_challenge_flag = True

test_pppoe_server_send_illegal_mru_option = False
test_pppoe_server_send_nak_magic_number_option = False
test_pppoe_server_send_reject_magic_number_option = True

while True:
	''''response to Ctrl+C keyboard'''
	if interrupted:
		padt = Ether(src=local_mac, dst=remote_mac)\
				/PPPoED(code=0xa7, sessionid=pppoe_sessionid)\
				/PPPoED_Tag(type=0x0203, data="Shutting Down")
		s.send(padt)
		print "exit from line %s" % (lineno())
		exit()
	
	ppp = s.recv()
	#print bytes(ppp).encode('hex')
	if ppp is None or ppp[Ether].src == local_mac:			#bypass the packet from local
		continue
	#if receive PADT, then exit
	elif ppp[Ether].type == 0x8863 and ppp[PPPoED].code == 0xa7:
		print "exit from line %s" % (lineno())
		exit()
	elif ppp[Ether].type == 0x8864:
		if ppp[PPP].proto == 0xc021:			#PPP LCP message
			if send_lcp_request_flag:
				ppp_lcp_request = Ether(src=local_mac, dst=remote_mac)\
						/PPPoE(code=0x00, sessionid=pppoe_sessionid)\
						/PPP()\
						/PPP_LCP(code=0x01)
						
				# if change the type of authentication, remember change the value of 'send_chap_challenge_flag' defined in the former
				# ppp_lcp_request.options = PPP_LCP_Option(type=0x03, data="\xc2\x23\x05")
				ppp_lcp_request.options = PPP_LCP_Option(type=0x05, data=magic_number)\
						/PPP_LCP_Option(type=0x03, data="\xc2\x23\x05")		#c023 is pap, c22305 is chap
						#/PPP_LCP_Option(type=0x03, data="\xc0\x23")
						# /PPP_LCP_Option(type=0x01, data="\x25\xd4")\
				if test_pppoe_server_send_illegal_mru_option:
					ppp_lcp_request.options = PPP_LCP_Option(type=0x05, data=magic_number)\
											/PPP_LCP_Option(type=0x03, data="\xc2\x23\x05")\
											/PPP_LCP_Option(type=0x01, data="\x00\xc7")
				
				s.send(ppp_lcp_request)
				send_lcp_request_flag = False

			if ppp[PPP_LCP].code in [1]: 	#PPP LCP Request
				ppp_lcp_reply = ppp.copy()
				ppp_lcp_reply[Ether].src = local_mac
				ppp_lcp_reply[Ether].dst = remote_mac
				ppp_lcp_reply[PPP_LCP].code = 2
				
				if test_pppoe_server_send_nak_magic_number_option:
					ppp_lcp_reply[PPP_LCP].code = 3
					s.send(ppp_lcp_reply)
					test_pppoe_server_send_nak_magic_number_option = False
					continue
				
				if test_pppoe_server_send_reject_magic_number_option:
					ppp_lcp_reply[PPP_LCP].code = 4
					s.send(ppp_lcp_reply)
					test_pppoe_server_send_reject_magic_number_option = False
					continue
				
				s.send(ppp_lcp_reply)
				
			elif ppp[PPP_LCP].code in [3]:
				ppp_lcp_request = Ether(src=local_mac, dst=remote_mac)\
						/PPPoE(code=0x00, sessionid=pppoe_sessionid)\
						/PPP()\
						/PPP_LCP(code=0x01)
				ppp_lcp_request.options = PPP_LCP_Option(type=0x05, data=magic_number)\
										/PPP_LCP_Option(type=0x03, data="\xc2\x23\x05")\
										/PPP_LCP_Option(type=0x01, data="\x00\xc7")
				s.send(ppp_lcp_request)
				
			elif ppp[PPP_LCP].code in [4]:
				ppp_lcp_request = Ether(src=local_mac, dst=remote_mac)\
						/PPPoE(code=0x00, sessionid=pppoe_sessionid)\
						/PPP()\
						/PPP_LCP(code=0x01)
				ppp_lcp_request.options = PPP_LCP_Option(type=0x05, data=magic_number)\
										/PPP_LCP_Option(type=0x03, data="\xc2\x23\x05")
				s.send(ppp_lcp_request)

			elif ppp[PPP_LCP].code in [9]: #receive ppp lcp echo request
				ppp_lcp_reply = ppp.copy()
				ppp_lcp_reply[Ether].src = local_mac
				ppp_lcp_reply[Ether].dst = remote_mac
				ppp_lcp_reply[PPP_LCP].code = 10
				ppp_lcp_reply[PPP_LCP].options = magic_number
	#			ppp_lcp_reply.show2()
				s.send(ppp_lcp_reply)
				
				ppp_lcp_echo_request = ppp.copy()
				ppp_lcp_echo_request[Ether].src = local_mac
				ppp_lcp_echo_request[Ether].dst = remote_mac
				ppp_lcp_echo_request[PPP_LCP].code = 0x09
				ppp_lcp_echo_request[PPP_LCP].options = magic_number
				s.send(ppp_lcp_echo_request)
				
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
					

		elif ppp[PPP].proto == 0xc223:				#CHAP message
			if ppp[PPP].code in [2]:				#receive CHAP response
				ppp_chap_reply = Ether()/PPPoE()/PPP()/PPP_CHAP()
				ppp_chap_reply[Ether].src =local_mac
				ppp_chap_reply[Ether].dst = remote_mac
				ppp_chap_reply[PPPoE].sessionid = ppp[PPPoE].sessionid
				ppp_chap_reply[PPP_CHAP].code = 0x03
				ppp_chap_reply[PPP_CHAP].data = "Login OK"
				s.send(ppp_chap_reply)

			
		elif ppp[PPP].proto == 0xc023:			#PPP PAP message
			if ppp[PPP].code in [1]:			#PPP PAP Request
				ppp_pap_reply = Ether()/PPPoE()/PPP()/PPP_PAP()
				ppp_pap_reply[Ether].src =local_mac
				ppp_pap_reply[Ether].dst = remote_mac
				ppp_pap_reply[PPPoE].sessionid = ppp[PPPoE].sessionid
				ppp_pap_reply[PPP_PAP].code = 0x02
				ppp_pap_reply[PPP_PAP].data = PPP_PAP_Data(data="Login OK")
				s.send(ppp_pap_reply)

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
							
							time.sleep(2)
							'''case 3: send other protocol PPP packets'''
							'''For Common Protocols Carried In PPP Frames and Protocol Field Values, refer to http://www.tcpipguide.com/free/t_PPPGeneralFrameFormat-3.htm'''
							'''
							0x29:	Appletalk
							0x2B:	Novell Internetworking Packet Exchange (IPX)
							0x3D:	PPP Multilink Protocol (MP) Fragment
							0x57:	Internet Protocol version 6 (IPv6)
							00FD:	Compressed Data (using CCP and a PPP compression algorithm)
							'''
							## for i in [0x21, 0x23, 0x29, 0x002B, 0x003D, 0x003F, 0x004D, 0x53, 0x55, 0x57, 0x00FB, 0x00FD, 0x4003, 0x4025, 0x8021, 0x8023, 0x8029, 0x802B, 0x803F, 0x804D, 0x8057, 0xC021, 0xC023, 0xC025, 0xC02B, 0xC02D, 0xC223]:
							# for i in [0x29, 0x002B, 0x003D, 0x57, 0x00FD]:
							for i in [0x00FD]:
								unsupported_ppp = Ether(src=local_mac, dst=remote_mac)\
									/PPPoE(code=0x00, sessionid=pppoe_sessionid)\
									/PPP(proto = i)
								s.send(unsupported_ppp)
								
							time.sleep(0.5)
							ppp_ipv6 = Ether(src=local_mac, dst=remote_mac)\
									/PPPoE(code=0x00, sessionid=pppoe_sessionid)\
									/PPP(proto = 0x0057)\
									/IPv6(src = "fe80:0:0:0:0:0:a00:1", dst = "fe80:0:0:0:0:0:a00:2")\
									/TCP()
							s.send(ppp_ipv6)
							
							# ppp_STP = Ether(src=local_mac, dst=remote_mac)\
									# /PPPoE(code=0x00, sessionid=pppoe_sessionid)\
									# /PPP(proto = 0x00FD)\
									# /IP(src = '10.0.0.1', dst = '10.0.0.2')
							# s.send(ppp_STP)
							
							time.sleep(0.5)
							ppp_ipv4 = Ether(src=local_mac, dst=remote_mac)\
									/PPPoE(code=0x00, sessionid=pppoe_sessionid)\
									/PPP(proto = 0x0021)\
									/IP(src = '10.0.0.1', dst = '10.0.0.2')\
									/ICMP()
							s.send(ppp_ipv4)

			elif ppp[PPP_IPCP].code in [2]:		#IPCP ACK
				#send ppp ipcp termination request
				None
				# break;
			elif ppp[PPP_IPCP].code in [3]:		#IPCP Nak
				ppp_ipcp = ppp;
				ppp_ipcp[Ether].src =local_mac
				ppp_ipcp[Ether].dst = remote_mac
				ppp_ipcp[PPP_IPCP].code = 0x01
				s.send(ppp_ipcp)
			elif ppp[PPP_IPCP].code in [4]:		#IPCP Reject
				None
s.close()