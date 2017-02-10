'''
Created on 2016年8月8日

@author: y35chen
'''

import requests
session = requests.session()
session.proxies = {'http':'http://10.144.1.10:8080',
                   'https':'https://10.144.1.10:8080'
                   }

r = session.get('https://www.python.org')
print(type(r))
print(r.status_code)
print(r.encoding)
print(r.cookies)

'''
r = session.get("a.json")
print(r.text)
print(r.json())
r = requests.get('https://github.com/timeline.json',stream=True)
r.raw
r.raw.read(10)

payload = {'key1':'value1','key2':'value2'}
headers = {'content-type':'application/json'}
r = requests.get("http://httpbin.org/get",params=payload,headers=headers)
print(r.url)

url = 'http://httpbin.org/post'
payload = {'some','data'}
r = requests.post(url, data=json.dump(payload))
print(r.text)
'''