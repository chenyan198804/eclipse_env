'''
Created on 2016年8月17日

@author: y35chen
'''
from urllib import request
proxy = request.ProxyHandler({'http':'http://10.144.1.10:8080'})
opener = request.build_opener(proxy)
request.install_opener(opener)  

old_url = 'http://www.baidu.com'
req = request.Request(old_url)
response = request.urlopen(req)
print('old url:'+old_url)
print('real url:'+response.geturl())
