'''
Created on 2016年8月18日

@author: y35chen
'''

import urllib.request
import urllib.parse
proxy = urllib.request.ProxyHandler({'http':'https://10.144.1.10:8080'})
opener = urllib.request.build_opener(proxy)
urllib.request.install_opener(opener)


url = 'http://www.someserver.com/cgi-bin/register.cgi'
value = {'name':'Michael Foord',
         'location':'Northampthon',
         'language':'Python'
         }
data = urllib.parse.urlencode(value)
data = data.encode('ascii')
req = urllib.request.Request(url,data)
with urllib.request.urlopen(req) as response:
    the_page = response.read()
print(the_page)