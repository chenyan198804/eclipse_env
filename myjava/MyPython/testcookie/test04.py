'''
Created on 2016年9月1日

@author: y35chen
'''
import urllib.parse
import urllib.request
import http.cookiejar
proxy = urllib.request.ProxyHandler({'http':'http://10.144.1.10:8080'})
filename = 'cookie.txt'
#声明一个MozillaCookieJar对象实例来保存cookie，之后写入文件
cookie = http.cookiejar.MozillaCookieJar(filename)
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie),proxy)
postdata = urllib.parse.urlencode({
                             'studi':'201200131012',
                             'pwd':'2334321'
                             })
#登录教务系统url
loginUrl = 'http://www.baidu.com'
#模拟登录，并把cookie保存到变量
result = opener.open(loginUrl,postdata)
#保存cookie到cookie，txt中
cookie.save(ignore_discard=True, ignore_expires=True)
#利用cookie请求访问另一个网址，此网址是成绩查询网址
gradeUrl = 'http://www.baidu.com'
#请求访问成绩查询网址
result = opener.open(gradeUrl,proxy)
print(result.read())