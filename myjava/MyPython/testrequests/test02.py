'''
Created on 2016年8月15日

@author: y35chen
'''
#-*- coding:utf-8 -*-
import requests
session = requests.session()
session.proxies = {'http':'http://10.144.1.10:8080',
                   'https':'https://10.144.1.10:8080'
                   }
url = 'http://news.163.com/rank/'
response = session.get(url)
print(response.text)