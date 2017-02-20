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

# from scapy.all import *
import inspect
import signal
import time
import os
import commands
import subprocess

interrupted = False

def signal_handler(signum, frame):
    global interrupted
    interrupted = True

signal.signal(signal.SIGINT, signal_handler)

def lineno():
    """Returns the current line number in our program."""
    return inspect.currentframe().f_back.f_lineno

#select the right interface, you can use command "get_if_list()", "get_if_hwaddr('eth0')", "get_if_addr('eth0')" to lookup interface
# if_list = get_if_list()
# ip_list = {}
# for interface in if_list:
	# ip_list[interface] = get_if_addr(interface)
# print ip_list
# conf.iface = 'eth1'

protocol_item = input("Select your test protocol: \n 1. IPv4\n 2. PPPoE\n 3. IPSec\n")

pppoe_scenario_name = [
		"AC-Cookie TAG and Other TAGs Support",
		"AC-Name TAG Support",
		"Authentication Protocol option",
		"Challenge Handshake Authentication Protocol support",
		"Counter Test over PPPoE&IPSec",
		"Host-Uniq TAG Support",
		"IP-Address option",
		"IPCP Code-Reject and IPCP Configure-Reject Packet",
		"IPCP Configure-Nak and IPCP Configure-Ack Packet",
		"IPCP_FAIL Alarm",
		"LCP Configure-Nak and LCP Configure-Reject Packet",
		"LCP Configure-Request Packets",
		"LCP other option",
		"LCP Terminate",
		"Magic-Number option",
		"Password Authentication Protocol support",
		"PPPoE Active Discovery Procedure",
		"PPPoE and PPP Special Considerations Test",
		"PPPoE Protocol and Number of PPP&PPPoE Sessions",
		"PPPoE Session Failure Alarm",
		"PPPoE Termination and Link Auto Recovery",
		"Supported LCP protocol messages",
]

pppoe_scenario_item = ''
i = 1
for item in pppoe_scenario_name:
	pppoe_scenario_item += "%2d. %s\n" % (i, item)
	i += 1

# print pppoe_scenario_item
# exit()

if protocol_item is 1:
	# print "1"
	while True:
		ipv4_scenario_item = input("Select your test scenario: \n1. ARP\n2. ICMP\n3. TCP\n4. UDP\n5. Exit\n")
		if ipv4_scenario_item is 5:
			exit()
		elif ipv4_scenario_item is 1:
			arp = ARP()
			arp.op=0x0001
			arp.hwdst = "00:00:00:00:00:00"
			arp.pdst = "10.69.196.147"
			arp.hwsrc = "00:00:00:00:00:01"
			arp.psrc = "10.69.196.92"
			send(arp)
		elif ipv4_scenario_item is 2:
			icmp = IP(src = '10.69.196.92', dst = '10.69.196.147')/ICMP()
			send(icmp)
		elif ipv4_scenario_item is 3:
			tcp = IP(src = '10.69.196.92', dst = '10.69.196.147')/TCP()
			send(tcp)
		elif ipv4_scenario_item is 4:
			udp = IP(src = '10.69.196.92', dst = '10.69.196.147')/UDP()
			send(udp)
elif protocol_item is 2:
    # print "2"
	while True:
		pppoe_scenario_select = input("Select your test scenario: \n" + pppoe_scenario_item + "99. Exit\n")
		if pppoe_scenario_select is 99:
			exit()
		# Counter_Test_over_PPPoE_IPSec.main()
		filename = r"E:\PackGen\\" + pppoe_scenario_name[pppoe_scenario_select-1] + ".py"
		cmd = 'python "%s"' % filename 
		os.system('python "%s"' % filename )
		# execfile( filename )
		# process = subprocess.Popen('python "%s"' % filename, shell=True)
		# os.system("start /wait cmd ipconfig")

elif protocol_item is 3:
    print "3"
else:
	print "the input is illegal."
	exit()