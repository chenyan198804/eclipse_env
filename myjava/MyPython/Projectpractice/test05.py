'''
Created on 2016年9月1日

@author: y35chen
'''
#-*- coding:utf-8 -*-
import urllib.request
from urllib.error import URLError
proxy = urllib.request.ProxyHandler({'http':'10.144.1.10:8080'})
opener = urllib.request.build_opener(proxy)
urllib.request.install_opener(opener)
page = 1
url = 'http://www.qiushibaike.com/hot/page/' + str(page)
try:
    request = urllib.request.Request(url)
    response = urllib.request.urlopen(url)
    print(response.read())
except URLError as e:
    if hasattr(e, "code"):
        print(e.code)
    if hasattr(e,"reason"):
        print(e.reason)