#!/usr/bin/env python
#_*_coding:utf-8_*_
import re 
'''
result1 = re.match('\d+','nsdai56nk23489')
if result1:
    print(result1.group())
else:
    print('nothing')
    
result2 = re.search('\d+','nsd56aink23489')
if result2:
    print(result2.group())
    
result3 =  re.findall('\d+', 'nsd56aink23489')
print(result3)

com = re.compile('\d+')
print(type(com))

print(com.findall('nsd56aink23489'))

result2 = re.search('(\d+)\w*(\d+)','nsd56aink12897877')
print(result2.group())
print(result2.groups())

result3 = re.search('a{3,5}', 'aaaaaaaaa')
print(result3.group())
'''

ip = '12.34.56.ssdafc.34kj999.998.295.888sd8c.di9sd.w.192.168.255.1@12jjdiadm,.da%4'
'''
result4 = re.findall('\d+', ip)
print(result4)
result5 = re.findall('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', ip)
print(result5)
'''
result6 = re.findall('(?:\d{1,3}\.){3}\d{1,3}',ip)
print(result6)
