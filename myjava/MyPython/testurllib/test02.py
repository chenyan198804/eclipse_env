'''
Created on 2016年8月24日

@author: y35chen
'''
import requests
r = requests.get('http://cuiqingcai.com')
print(type(r))
print(r.status_code)
print(r.encoding)