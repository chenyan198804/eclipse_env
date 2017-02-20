from scapy.all import *
import glob
import os
import subprocess

tshark = r"C:\BS3002_Tools\MMT\tshark.exe"
mmt_filter = r"xml.tag contains \"pmDataRsp\""
timestamp = []

os.chdir("E:\\wangjia_mansho\\MMT-05\\mmt\\")

fileHandle = open ( 'E:\\wangjia_mansho\\MMT-05\\result.txt', 'w' )  
fileHandle_tmp = open ( 'E:\\wangjia_mansho\\MMT-05\\tmp.txt', 'w' )  

for mmt_file in glob.glob("1_00*"):
	new_mmt_file = "new_" + mmt_file
	# cmd = tshark  + "-r" + mmt_file mmt_filter, new_mmt_file))
	# os.system('"%s" -r "%s" -R "%s" -w "%s"' % (tshark, mmt_file, mmt_filter, new_mmt_file))
	subprocess.call('"%s" -r "%s" -R "%s" -w "%s"' % (tshark, mmt_file, mmt_filter, new_mmt_file))
	mmt_pcap = rdpcap(new_mmt_file)
	t = []
	for p in mmt_pcap:
		t.append(p.time)
		
	timestamp.append(t)
	print mmt_file
	
start = timestamp[0][0] - 2
for i in xrange(0, len(timestamp)):
	for j in xrange(0, len(timestamp[i])):
		diff = timestamp[i][j] - start
		# print "%f" % diff
		fileHandle_tmp.write( "%f\n" % diff)
		# if abs(diff - 2) > pow(10, -2):
		if abs(diff - 2) > 5.0e-2:
			print "%d, %d" % (i+1, j+1)
			fileHandle.write ( "%d, %d\n" % (i+1, j+1) ) 
			# exit()
		start = timestamp[i][j]

fileHandle.close() 
fileHandle_tmp.close()
