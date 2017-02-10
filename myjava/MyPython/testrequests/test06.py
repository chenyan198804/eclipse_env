'''
Created on 2016年8月26日

@author: y35chen
'''
import urllib.request
enable_proxy = True
proxy_handler = urllib.request.ProxyHandler({'http':'http://10.144.1.10:8080'})
null_proxy_handler = urllib.request.ProxyHandler({})
if enable_proxy:
    opener = urllib.request.build_opener(proxy_handler)
else:
    opener = urllib.request.build_opener(null_proxy_handler)
urllib.request.install_opener(opener)