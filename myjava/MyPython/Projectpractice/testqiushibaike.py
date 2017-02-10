'''
Created on 2016年8月10日
测试糗事百科
@author: y35chen
'''
#-*- coding:utf-8 -*-
import re
import urllib.request
from urllib.error import URLError

proxy = urllib.request.ProxyHandler({'http':'http://10.144.1.10:8080'})
opener = urllib.request.build_opener(proxy)
urllib.request.install_opener(opener)
  
page = 1
url = 'http://www.qiushibaike.com/hot/page/' + str(page)
user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
headers = { 'User-Agent' : user_agent }
try:
    request = urllib.request.Request(url,headers = headers)
    response = urllib.request.urlopen(request,timeout=5)
    content = response.read().decode('utf-8')
    pattern=re.compile('<div class="author clearfix">.*?<h2>(.*?)</h2>.*?<div class="content">(.*?)</div>.*?<div class="stats".*?i class="number">(.*?)</i>(.*?)</span>.*?<span class="dash".*?i class="number">(.*?)</i>(.*?)</a>',re.S)
    items = re.findall(pattern,content)
    for item in items:
        haveImg = re.search('img',item[3])
        if not haveImg:
            print(item[0],item[1],item[2],item[4])
except URLError as e: 
    if hasattr(e,"code"):
        print(e.code)
    if hasattr(e,"reason"):
        print(e.reason)


