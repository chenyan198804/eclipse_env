'''
Created on 2016年8月31日

@author: y35chen
'''
import urllib.request
import http.cookiejar
cookie = http.cookiejar.CookieJar()
proxy = urllib.request.ProxyHandler({'http':'http://10.144.1.10:8080'})
handler = urllib.request.HTTPCookieProcessor(cookie)
opener = urllib.request.build_opener(handler,proxy)
response = opener.open('http://www.baidu.com')
for item in cookie:
    print('Name='+item.name)
    print('Value='+item.value)