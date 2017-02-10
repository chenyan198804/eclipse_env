'''
Created on 2016年9月1日

@author: y35chen
'''
import urllib.request
import http.cookiejar
proxy = urllib.request.ProxyHandler({'http':'http://10.144.1.10:8080'})
cookie = http.cookiejar.MozillaCookieJar()
cookie.load('cookie.txt',ignore_discard=True,ignore_expires=True)
req = urllib.request.Request("http://www.baidu.com")
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie),proxy)
response = opener.open(req)
print(response.read())