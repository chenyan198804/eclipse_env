'''
Created on 2016年8月10日

@author: y35chen
'''
import urllib.request
proxy = urllib.request.ProxyHandler({'http':'http://10.144.1.10:8080'})
opener0 = urllib.request.build_opener(proxy)
urllib.request.install_opener(opener0)
#create a password Manager
password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
#Add the username and Password
#If we knew the realm, we could use it instead of None
top_level_url = 'http://www.baidu.com'
password_mgr.add_password(None, top_level_url, 'rekfan', '123456')
handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
#create 'opener'(OpenerDirector_instance)
opener = urllib.request.build_opener(handler)
#user the opener to fetch a URL 
a_url = 'http://www.baidu.com'
x = opener.open(a_url)
print(x.read())
#Install the opener
#Now all calls to urllib.request.urlopen use our opener
urllib.request.install_opener(opener)
a = urllib.request.urlopen(a_url).read().decode('utf8')
print(a)