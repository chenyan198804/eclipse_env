'''
Created on 2016年8月10日

@author: y35chen
'''
import urllib.parse  
import urllib.request  
url = ''  
user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'  
values = {  
'act' : 'login',  
'login[email]' : '',  
'login[password]' : ''  
}  
headers = { 'User-Agent' : user_agent }  
data = urllib.parse.urlencode(values)  
req = urllib.request.Request(url, data, headers)  
response = urllib.request.urlopen(req)  
the_page = response.read()  
print(the_page.decode("utf8"))

