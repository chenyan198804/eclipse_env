'''
Created on 2016年8月31日

@author: y35chen
'''
import urllib.request
import http.cookiejar
filename = 'cookie.txt'
cookie = http.cookiejar.MozillaCookieJar(filename)
proxy = urllib.request.ProxyHandler({'http':'http://10.144.1.10:8080'})
handler = urllib.request.HTTPCookieProcessor(cookie)
opener = urllib.request.build_opener(handler,proxy)
response = opener.open("http://www.baidu.com")
cookie.save(ignore_discard=True, ignore_expires=True)

