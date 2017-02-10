'''
Created on 2016年8月8日

@author: y35chen
'''

import urllib.parse
import urllib.request
proxy = urllib.request.ProxyHandler({'http':'http://10.144.1.10:8080'})
opener = urllib.request.build_opener(proxy)
urllib.request.install_opener(opener)
url = 'http://www.baidu.com'
user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'  
values = {  
'act' : 'login',  
'login[email]' : '',  
'login[password]' : ''  
}  
headers = { 'User-Agent' : user_agent }  
data = urllib.parse.urlencode(values).encode(encoding='UTF8')
request = urllib.request.Request(url, data, headers)  
response = urllib.request.urlopen(request)  
the_page = response.read()
print(the_page.decode("utf8"))
