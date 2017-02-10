#-*- coding:utf-8 -*-
import urllib.request
import re

proxy = urllib.request.ProxyHandler({'http':'http://10.144.1.10:8080'})
opener = urllib.request.build_opener(proxy)
urllib.request.install_opener(opener)


response = urllib.request.urlopen('http://data.eastmoney.com/stockcomment/001979.html')
html = response.read()
print(html)
html = html.decode('GBK')

f = re.search("(\d+.\d+%)", html)
if f:
    print(f.group(1))
