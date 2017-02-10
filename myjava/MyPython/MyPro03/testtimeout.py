'''
Created on 2016年8月10日

@author: y35chen
'''
import socket  
import urllib.request  
proxy = urllib.request.ProxyHandler({'http':'http://10.144.1.10:8080'})
opener = urllib.request.build_opener(proxy)
urllib.request.install_opener(opener)
# timeout in seconds  
timeout = 2  
socket.setdefaulttimeout(timeout)  
# this call to urllib.request.urlopen now uses the default timeout  
# we have set in the socket module  
req = urllib.request.Request('http://www.baidu.com')  
a = urllib.request.urlopen(req).read()  
print(a)  