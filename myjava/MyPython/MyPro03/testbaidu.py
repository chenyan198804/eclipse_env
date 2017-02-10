'''
Created on 2016年8月15日

@author: y35chen
'''
import urllib.request
proxy = urllib.request.ProxyHandler({'http':'http://10.144.1.10:8080'})
opener = urllib.request.build_opener(proxy)
urllib.request.install_opener(opener)
response = urllib.request.urlopen('http://www.baidu.com')
html = response.read()
print(html)
