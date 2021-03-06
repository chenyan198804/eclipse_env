﻿#! /usr/bin/env python
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
host_uniq = "\x01\x02\x03\x04"

#ans = srp1(pppoe)

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
		
		#Host-Uniq tag is equal to PADI's Host-Uniq tag
		pado = Ether(src=local_mac, dst=remote_mac)\
				/PPPoED(code=0x07)\
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
				
		#Host-Uniq tag is not equal to PADR's Host-Uniq tag
		pads = Ether(src=local_mac, dst=remote_mac)\
				/PPPoED(code=0x65, sessionid=pppoe_sessionid)\
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
send_lcp_other_request_flag = True
send_ipcp_request_flag = True
send_chap_challenge_flag = True

test_pppoe_server_send_ipcp_configure_request_with_null_option  = False
# test_pppoe_server_send_ipcp_with_illegal_code = True
test_pppoe_server_send_ipcp_with_illegal_code_1 = False
test_pppoe_server_send_ipcp_with_legal_code = True
ipcp_code_counter = 1;

test_pppoe_server_reply_legal_ipcp_code_reject = False
test_pppoe_server_reply_illegal_ipcp_code_reject = False

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
						/PPP_LCP_Option(type=0x03, data="\xc0\x23")
						# /PPP_LCP_Option(type=0x03, data="\xc2\x23\x05")		#c023 is pap, c22305 is chap
						# /PPP_LCP_Option(type=0x01, data="\x25\xd4")\
						
				s.send(ppp_lcp_request)
				send_lcp_request_flag = False
			
			'''case 01: send LCP other request in non-opened state'''
			# if send_lcp_other_request_flag:
				# for i in xrange(0x0b, 0x100):
					# ppp_lcp_discard_request = Ether(src=local_mac, dst=remote_mac)\
						# /PPPoE(code=0x00, sessionid=pppoe_sessionid)\
						# /PPP()\
						# /PPP_LCP(code = i)
					# ppp_lcp_discard_request.options = magic_number
					# s.send(ppp_lcp_discard_request)
				# send_lcp_other_request_flag = False

			if ppp[PPP_LCP].code in [1]: 	#PPP LCP Request
	#			ppp.show2()
	#			print "-----------------"
				 
				ppp_lcp_reply = ppp.copy()
				ppp_lcp_reply[Ether].src = local_mac
				ppp_lcp_reply[Ether].dst = remote_mac
				ppp_lcp_reply[PPP_LCP].code = 2
				s.send(ppp_lcp_reply)
				
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
				
				'''case 02: send LCP other request in opened state'''
				# if send_lcp_other_request_flag:
					# for i in xrange(0x0b, 0x100):
						# ppp_lcp_discard_request = Ether(src=local_mac, dst=remote_mac)\
							# /PPPoE(code=0x00, sessionid=pppoe_sessionid)\
							# /PPP()\
							# /PPP_LCP(id = i, code = i)
						# ppp_lcp_discard_request.options = PPP_LCP_Option(type=0x05, data=magic_number)
						# s.send(ppp_lcp_discard_request)
					# send_lcp_other_request_flag = False
				
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

				if test_pppoe_server_send_ipcp_with_illegal_code_1:
					for i in xrange(8, 256):
						ppp_ipcp_request = Ether()/PPPoE()/PPP()/PPP_IPCP()
						ppp_ipcp_request[Ether].src =local_mac
						ppp_ipcp_request[Ether].dst = remote_mac
						ppp_ipcp_request[PPPoE].sessionid = ppp[PPPoE].sessionid
						ppp_ipcp_request[PPP].proto = 0x8021
						ppp_ipcp_request[PPP_IPCP].id = i
						ppp_ipcp_request[PPP_IPCP].code = i
						ppp_ipcp_request[PPP_IPCP].options = ""
						s.send(ppp_ipcp_request)
					test_pppoe_server_send_ipcp_with_illegal_code_1 = False
				
		elif ppp[PPP].proto == 0x8021:
			if test_pppoe_server_send_ipcp_with_legal_code and ipcp_code_counter < 8:
				ppp_ipcp_request = Ether()/PPPoE()/PPP()/PPP_IPCP()
				ppp_ipcp_request[Ether].src =local_mac
				ppp_ipcp_request[Ether].dst = remote_mac
				ppp_ipcp_request[PPPoE].sessionid = ppp[PPPoE].sessionid
				ppp_ipcp_request[PPP].proto = 0x8021
				ppp_ipcp_request[PPP_IPCP].id = ppp[PPP_IPCP].id
				ppp_ipcp_request[PPP_IPCP].code = ipcp_code_counter
				ipcp_code_counter += 1
				ppp_ipcp_request[PPP_IPCP].options = ""
				s.send(ppp_ipcp_request)
				continue
					
			if ppp[PPP_IPCP].code in [1]:				#ppp ipcp request
				ppp_ipcp_reply = ppp.copy();
				ppp_ipcp_reply[Ether].src =local_mac
				ppp_ipcp_reply[Ether].dst = remote_mac

				if test_pppoe_server_reply_legal_ipcp_code_reject:
					ppp_ipcp_reply = Ether()/PPPoE()/PPP()/PPP_IPCP()
					ppp_ipcp_reply[Ether].src =local_mac
					ppp_ipcp_reply[Ether].dst = remote_mac
					ppp_ipcp_reply[PPPoE].sessionid = ppp[PPPoE].sessionid
					ppp_ipcp_reply[PPP].proto = ppp[PPP].proto
					ppp_ipcp_reply[PPP_IPCP].code = 0x07
					ppp_ipcp_reply[PPP_IPCP].options = str(ppp[PPP_IPCP])
					s.send(ppp_ipcp_reply)
					print "exit from line %s" % (lineno())
					exit()

				if test_pppoe_server_reply_illegal_ipcp_code_reject:
					ppp_ipcp_reply = Ether()/PPPoE()/PPP()/PPP_IPCP()
					ppp_ipcp_reply[Ether].src =local_mac
					ppp_ipcp_reply[Ether].dst = remote_mac
					ppp_ipcp_reply[PPPoE].sessionid = ppp[PPPoE].sessionid
					ppp_ipcp_reply[PPP].proto = ppp[PPP].proto
					ppp_ipcp_reply[PPP_IPCP].code = 0x07
					# ppp_ipcp_reply[PPP_IPCP].options = '\x01\x02\x03\x04' + str(ppp[PPP_IPCP])
					ppp_ipcp_reply[PPP_IPCP].options = '\x02'*10
					s.send(ppp_ipcp_reply)
					test_pppoe_server_reply_illegal_ipcp_code_reject = False
					continue

				if send_ipcp_request_flag:
					ppp_ipcp_request = Ether()/PPPoE()/PPP()/PPP_IPCP()
					ppp_ipcp_request[Ether].src =local_mac
					ppp_ipcp_request[Ether].dst = remote_mac
					ppp_ipcp_request[PPPoE].sessionid = ppp[PPPoE].sessionid
					ppp_ipcp_request[PPP].proto = 0x8021
					ppp_ipcp_request[PPP_IPCP].id = 0x01
					
					# ppp_ipcp_request[PPP_IPCP].options = PPP_IPCP_Option_IPAddress(data="127.0.0.1")
					ppp_ipcp_request[PPP_IPCP].options = PPP_IPCP_Option_IPAddress(data="10.0.0.1")
					ppp_ipcp_request[PPP_IPCP].code = 0x01
					
					if test_pppoe_server_send_ipcp_configure_request_with_null_option:
						ppp_ipcp_request[PPP_IPCP].options = ""
			
					s.send(ppp_ipcp_request)
					send_ipcp_request_flag = False
				
				if len(ppp[PPP_IPCP].options) == 0:
					ppp_ipcp_reject_null_option = Ether()/PPPoE()/PPP()/PPP_IPCP()
					ppp_ipcp_reject_null_option[Ether].src = local_mac
					ppp_ipcp_reject_null_option[Ether].dst = remote_mac
					ppp_ipcp_reject_null_option[PPPoE].sessionid = ppp[PPPoE].sessionid
					ppp_ipcp_reject_null_option[PPP].proto = 0x8021
					ppp_ipcp_reject_null_option[PPP_IPCP].id = ppp[PPP_IPCP].id
					s.send(ppp_ipcp_reject_null_option)
					continue
					
				for ipcp_option in ppp[PPP_IPCP].options:
					if type(ipcp_option) is PPP_IPCP_Option_IPAddress:
						# hexdump(ipcp_option)
						if ipcp_option.data == "0.0.0.0":
							ppp_ipcp_reply[PPP_IPCP].code = 0x03
							ppp_ipcp_reply[PPP_IPCP_Option_IPAddress].data = "10.0.0.2"
							s.send(ppp_ipcp_reply)
						else:
							ppp_ipcp_reply[PPP_IPCP].code = 0x02
							s.send(ppp_ipcp_reply)

							ppp_ipv4 = Ether(src=local_mac, dst=remote_mac)\
									/PPPoE(code=0x00, sessionid=pppoe_sessionid)\
									/PPP(proto = 0x0021)\
									/IP(src = '10.0.0.1', dst = '10.0.0.2')\
									/ICMP()
							s.send(ppp_ipv4)
							
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
				if test_pppoe_server_send_ipcp_configure_request_with_null_option:
					ppp_ipcp_request = Ether()/PPPoE()/PPP()/PPP_IPCP()
					ppp_ipcp_request[Ether].src =local_mac
					ppp_ipcp_request[Ether].dst = remote_mac
					ppp_ipcp_request[PPPoE].sessionid = ppp[PPPoE].sessionid
					ppp_ipcp_request[PPP].proto = 0x8021
					ppp_ipcp_request[PPP_IPCP].id = 0x02
					ppp_ipcp_request[PPP_IPCP].options = PPP_IPCP_Option_IPAddress(data="10.0.0.1")
					s.send(ppp_ipcp_request)
s.close()