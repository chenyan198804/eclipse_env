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

'''
the following PPP_TYPE contains 149 types, the BTS only support following types. So the capture should
display 144 LCP Reject packets.
0021:	IPv4
8021:	IPCP
C021:	LCP
C023:	PAP
C223:	CHAP
'''
PPP_TYPE = { 0x0001: "Padding Protocol",
               0x0003: "ROHC small-CID [RFC3095]",
               0x0005: "ROHC large-CID [RFC3095]",
               0x0021: "Internet Protocol version 4",
               0x0023: "OSI Network Layer",
               0x0025: "Xerox NS IDP",
               0x0027: "DECnet Phase IV",
               0x0029: "Appletalk",
               0x002b: "Novell IPX",
               0x002d: "Van Jacobson Compressed TCP/IP",
               0x002f: "Van Jacobson Uncompressed TCP/IP",
               0x0031: "Bridging PDU",
               0x0033: "Stream Protocol (ST-II)",
               0x0035: "Banyan Vines",
               0x0037: "reserved (until 1993) [Typo in RFC1172]",
               0x0039: "AppleTalk EDDP",
               0x003b: "AppleTalk SmartBuffered",
               0x003d: "Multi-Link [RFC1717]",
               0x003f: "NETBIOS Framing",
               0x0041: "Cisco Systems",
               0x0043: "Ascom Timeplex",
               0x0045: "Fujitsu Link Backup and Load Balancing (LBLB)",
               0x0047: "DCA Remote Lan",
               0x0049: "Serial Data Transport Protocol (PPP-SDTP)",
               0x004b: "SNA over 802.2",
               0x004d: "SNA",
               0x004f: "IPv6 Header Compression",
               0x0051: "KNX Bridging Data [ianp]",
               0x0053: "Encryption [Meyer]",
               0x0055: "Individual Link Encryption [Meyer]",
               0x0057: "Internet Protocol version 6 [Hinden]",
               0x0059: "PPP Muxing [RFC3153]",
               0x005b: "Vendor-Specific Network Protocol (VSNP) [RFC3772]",
               0x0061: "RTP IPHC Full Header [RFC3544]",
               0x0063: "RTP IPHC Compressed TCP [RFC3544]",
               0x0065: "RTP IPHC Compressed Non TCP [RFC3544]",
               0x0067: "RTP IPHC Compressed UDP 8 [RFC3544]",
               0x0069: "RTP IPHC Compressed RTP 8 [RFC3544]",
               0x006f: "Stampede Bridging",
               0x0071: "Reserved [Fox]",
               0x0073: "MP+ Protocol [Smith]",
               0x007d: "reserved (Control Escape) [RFC1661]",
               0x007f: "reserved (compression inefficient [RFC1662]",
               0x0081: "Reserved Until 20-Oct-2000 [IANA]",
               0x0083: "Reserved Until 20-Oct-2000 [IANA]",
               0x00c1: "NTCITS IPI [Ungar]",
               0x00cf: "reserved (PPP NLID)",
               0x00fb: "single link compression in multilink [RFC1962]",
               0x00fd: "compressed datagram [RFC1962]",
               0x00ff: "reserved (compression inefficient)",
               0x0201: "802.1d Hello Packets",
               0x0203: "IBM Source Routing BPDU",
               0x0205: "DEC LANBridge100 Spanning Tree",
               0x0207: "Cisco Discovery Protocol [Sastry]",
               0x0209: "Netcs Twin Routing [Korfmacher]",
               0x020b: "STP - Scheduled Transfer Protocol [Segal]",
               0x020d: "EDP - Extreme Discovery Protocol [Grosser]",
               0x0211: "Optical Supervisory Channel Protocol (OSCP)[Prasad]",
               0x0213: "Optical Supervisory Channel Protocol (OSCP)[Prasad]",
               0x0231: "Luxcom",
               0x0233: "Sigma Network Systems",
               0x0235: "Apple Client Server Protocol [Ridenour]",
               0x0281: "MPLS Unicast [RFC3032]  ",
               0x0283: "MPLS Multicast [RFC3032]",
               0x0285: "IEEE p1284.4 standard - data packets [Batchelder]",
               0x0287: "ETSI TETRA Network Protocol Type 1 [Nieminen]",
               0x0289: "Multichannel Flow Treatment Protocol [McCann]",
               0x2063: "RTP IPHC Compressed TCP No Delta [RFC3544]",
               0x2065: "RTP IPHC Context State [RFC3544]",
               0x2067: "RTP IPHC Compressed UDP 16 [RFC3544]",
               0x2069: "RTP IPHC Compressed RTP 16 [RFC3544]",
               0x4001: "Cray Communications Control Protocol [Stage]",
               0x4003: "CDPD Mobile Network Registration Protocol [Quick]",
               0x4005: "Expand accelerator protocol [Rachmani]",
               0x4007: "ODSICP NCP [Arvind]",
               0x4009: "DOCSIS DLL [Gaedtke]",
               0x400B: "Cetacean Network Detection Protocol [Siller]",
               0x4021: "Stacker LZS [Simpson]",
               0x4023: "RefTek Protocol [Banfill]",
               0x4025: "Fibre Channel [Rajagopal]",
               0x4027: "EMIT Protocols [Eastham]",
               0x405b: "Vendor-Specific Protocol (VSP) [RFC3772]",
               0x8021: "Internet Protocol Control Protocol",
               0x8023: "OSI Network Layer Control Protocol",
               0x8025: "Xerox NS IDP Control Protocol",
               0x8027: "DECnet Phase IV Control Protocol",
               0x8029: "Appletalk Control Protocol",
               0x802b: "Novell IPX Control Protocol",
               0x802d: "reserved",
               0x802f: "reserved",
               0x8031: "Bridging NCP",
               0x8033: "Stream Protocol Control Protocol",
               0x8035: "Banyan Vines Control Protocol",
               0x8037: "reserved (until 1993)",
               0x8039: "reserved",
               0x803b: "reserved",
               0x803d: "Multi-Link Control Protocol",
               0x803f: "NETBIOS Framing Control Protocol",
               0x8041: "Cisco Systems Control Protocol",
               0x8043: "Ascom Timeplex",
               0x8045: "Fujitsu LBLB Control Protocol",
               0x8047: "DCA Remote Lan Network Control Protocol (RLNCP)",
               0x8049: "Serial Data Control Protocol (PPP-SDCP)",
               0x804b: "SNA over 802.2 Control Protocol",
               0x804d: "SNA Control Protocol",
               0x804f: "IP6 Header Compression Control Protocol",
               0x8051: "KNX Bridging Control Protocol [ianp]",
               0x8053: "Encryption Control Protocol [Meyer]",
               0x8055: "Individual Link Encryption Control Protocol [Meyer]",
               0x8057: "IPv6 Control Protovol [Hinden]",
               0x8059: "PPP Muxing Control Protocol [RFC3153]",
               0x805b: "Vendor-Specific Network Control Protocol (VSNCP) [RFC3772]",
               0x806f: "Stampede Bridging Control Protocol",
               0x8073: "MP+ Control Protocol [Smith]",
               0x8071: "Reserved [Fox]",
               0x807d: "Not Used - reserved [RFC1661]",
               0x8081: "Reserved Until 20-Oct-2000 [IANA]",
               0x8083: "Reserved Until 20-Oct-2000 [IANA]",
               0x80c1: "NTCITS IPI Control Protocol [Ungar]",
               0x80cf: "Not Used - reserved [RFC1661]",
               0x80fb: "single link compression in multilink control [RFC1962]",
               0x80fd: "Compression Control Protocol [RFC1962]",
               0x80ff: "Not Used - reserved [RFC1661]",
               0x8207: "Cisco Discovery Protocol Control [Sastry]",
               0x8209: "Netcs Twin Routing [Korfmacher]",
               0x820b: "STP - Control Protocol [Segal]",
               0x820d: "EDPCP - Extreme Discovery Protocol Ctrl Prtcl [Grosser]",
               0x8235: "Apple Client Server Protocol Control [Ridenour]",
               0x8281: "MPLSCP [RFC3032]",
               0x8285: "IEEE p1284.4 standard - Protocol Control [Batchelder]",
               0x8287: "ETSI TETRA TNP1 Control Protocol [Nieminen]",
               0x8289: "Multichannel Flow Treatment Protocol [McCann]",
               0xc021: "Link Control Protocol",
               0xc023: "Password Authentication Protocol",
               0xc025: "Link Quality Report",
               0xc027: "Shiva Password Authentication Protocol",
               0xc029: "CallBack Control Protocol (CBCP)",
               0xc02b: "BACP Bandwidth Allocation Control Protocol [RFC2125]",
               0xc02d: "BAP [RFC2125]",
               0xc05b: "Vendor-Specific Authentication Protocol (VSAP) [RFC3772]",
               0xc081: "Container Control Protocol [KEN]",
               0xc223: "Challenge Handshake Authentication Protocol",
               0xc225: "RSA Authentication Protocol [Narayana]",
               0xc227: "Extensible Authentication Protocol [RFC2284]",
               0xc229: "Mitsubishi Security Info Exch Ptcl (SIEP) [Seno]",
               0xc26f: "Stampede Bridging Authorization Protocol",
               0xc281: "Proprietary Authentication Protocol [KEN]",
               0xc283: "Proprietary Authentication Protocol [Tackabury]",
               0xc481: "Proprietary Node ID Authentication Protocol [KEN]"}


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

test_pppoe_server_reply_code_reject_to_config_request = True

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
			
			if test_pppoe_server_reply_code_reject_to_config_request == True:
				ppp_lcp_discard_request = Ether(src=local_mac, dst=remote_mac)\
							/PPPoE(code=0x00, sessionid=pppoe_sessionid)\
							/PPP()\
							/PPP_LCP(id = 1, code = 7)
				# ppp_lcp_discard_request.options = PPP_LCP_Option(type=0x05, data='\x01\x02\x03\x04')
				# ppp_lcp_discard_request.options = "\x01\x02\x03\x04"
				ppp_lcp_discard_request.options = "\x03\x03\x03\x04"
				s.send(ppp_lcp_discard_request)
				
				test_pppoe_server_reply_code_reject_to_config_request = False
				
				print "************send(pado)************"
				break
			
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
				
				ppp_ipcp_request = Ether()/PPPoE()/PPP()/PPP_IPCP()
				ppp_ipcp_request[Ether].src =local_mac
				ppp_ipcp_request[Ether].dst = remote_mac
				ppp_ipcp_request[PPPoE].sessionid = ppp[PPPoE].sessionid
				ppp_ipcp_request[PPP].proto = 0x8021
				ppp_ipcp_request[PPP_IPCP].id = 0x01
				ppp_ipcp_request[PPP_IPCP].options = PPP_IPCP_Option_IPAddress(data="10.0.0.1")
				s.send(ppp_ipcp_request)
			
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
							# for i in [0x00FD]:
							# for i in PPP_TYPE:
								# unsupported_ppp = Ether(src=local_mac, dst=remote_mac)\
									# /PPPoE(code=0x00, sessionid=pppoe_sessionid)\
									# /PPP(proto = i)
								# s.send(unsupported_ppp)
								# time.sleep(0.1)
								
							# time.sleep(0.5)
							# ppp_ipv6 = Ether(src=local_mac, dst=remote_mac)\
									# /PPPoE(code=0x00, sessionid=pppoe_sessionid)\
									# /PPP(proto = 0x0057)\
									# /IPv6(src = "fe80:0:0:0:0:0:a00:1", dst = "fe80:0:0:0:0:0:a00:2")\
									# /TCP()
							# s.send(ppp_ipv6)
							
							# ppp_STP = Ether(src=local_mac, dst=remote_mac)\
									# /PPPoE(code=0x00, sessionid=pppoe_sessionid)\
									# /PPP(proto = 0x00FD)\
									# /IP(src = '10.0.0.1', dst = '10.0.0.2')
							# s.send(ppp_STP)
							
							# time.sleep(0.5)
							# ppp_ipv4 = Ether(src=local_mac, dst=remote_mac)\
									# /PPPoE(code=0x00, sessionid=pppoe_sessionid)\
									# /PPP(proto = 0x0021)\
									# /IP(src = '10.0.0.1', dst = '10.0.0.2')\
									# /ICMP()
							# s.send(ppp_ipv4)
							
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