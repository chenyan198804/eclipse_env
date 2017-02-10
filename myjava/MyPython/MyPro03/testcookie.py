'''
Created on 2016年8月9日

@author: y35chen
'''
import http.cookiejar
import urllib.request
'''
def getOpener(head):
    #deal with the Cookies 
    cj = http.cookiejar.CookieJar()
    pro = urllib.request.HTTPCookieProcessor(cj)
    opener = urllib.request.build_opener(pro)
    header = []
    for key, value in head.items():
        elem = (key, value)
        head.append(elem)
    opener.addheaders = header
    return opener

'''
proxy = urllib.request.ProxyHandler({'http':'http://10.144.1.10:8080'})
opener0 = urllib.request.build_opener(proxy)
urllib.request.install_opener(opener0)

#声明一个CookieJar对象实例来保存cookie
cookie = http.cookiejar.CookieJar()
#利用urllib2库的HTTPCookieProcessor对象来创建cookie处理器
handler = urllib.request.HTTPCookieProcessor(cookie)
#通过handler来构建opener
opener = urllib.request.build_opener(handler)
#此处的open方法同urllib2的urlopen方法，也可以传入request
response = opener.open('https://www.baidu.com')
for item in cookie:
    print('Name = '+item.name)
    print('Value = '+item.value)

