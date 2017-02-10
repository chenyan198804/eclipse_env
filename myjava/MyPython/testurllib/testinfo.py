'''
Created on 2016年8月18日

@author: y35chen
'''
import sysconfig
from urllib.request import Request,urlopen,ProxyHandler,build_opener,install_opener

proxy = ProxyHandler({'http':'https://10.144.1.10:8080'})
opener = build_opener(proxy)
install_opener(opener)

old_url = 'http://www.baidu.com'
req = Request(old_url)
response = urlopen(req)
print('Info():')
print('response.info()')