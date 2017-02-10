'''
Created on 2016年8月18日
http://www.lining0806.com/1-%E6%9C%80%E5%9F%BA%E6%9C%AC%E7%9A%84%E7%88%AC%E8%99%AB/
@author: y35chen
'''
import requests
import urllib.request
proxy = urllib.request.ProxyHandler({'http':'http://10.144.1.10:8080'})
opener = urllib.request.build_opener(proxy)
urllib.request.install_opener(opener)
response = urllib.request.urlopen('http://www.baidu.com')
html = response.read()
print(html.decode("utf-8"))
'''url = 'http://www.baidu.com'
response = requests.get(url)
content = requests.get(url).content
print(content.decode("utf-8"))
'''
