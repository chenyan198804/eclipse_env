'''
Created on 2016年8月9日

@author: y35chen
'''
'''
import urllib.request
req = urllib.request.Request('http://www.baidu.com')
try:
    urllib.request.urlopen(req)
except urllib.error.HTTPError as e:
    print(e.reason)
'''    
'''
import urllib.request  
proxy = urllib.request.ProxyHandler({'http':'http://10.144.1.10:8080'})
opener = urllib.request.build_opener(proxy)
urllib.request.install_opener(opener)
req = urllib.request.Request('http://www.baidu.com')  
try:  
    urllib.request.urlopen(req)  
except urllib.error.HTTPError as e:  
    print(e.code)  
    print(e.read().decode("utf8"))  
    '''
'''
import urllib
from urllib.request import Request, urlopen  
from urllib.error import URLError, HTTPError 
proxy = urllib.request.ProxyHandler({'http':'http://10.144.1.10:8080'})
opener = urllib.request.build_opener(proxy)
urllib.request.install_opener(opener) 
req = Request('http://www.baidu.com')  
try:  
    response = urlopen(req)  
except HTTPError as e:  
    print('The server could not fulfill the request.')  
    print('Error code: ', e.code)  
except URLError as e:  
    print('We failed to reach a server.')  
    print('Reason: ', e.reason)  
else:  
    print("good!")  
    print(response.read().decode("utf8"))  
    '''
import urllib
from urllib.request import Request, urlopen  
from urllib.error import URLError
proxy = urllib.request.ProxyHandler({'http':'http://10.144.1.10:8080'})
opener = urllib.request.build_opener(proxy)
urllib.request.install_opener(opener)  
req = Request('http://www.baidu.com')  
try:  
    response = urlopen(req)  
except URLError as e:  
    if hasattr(e, 'reason'):  
        print('We failed to reach a server.')  
        print('Reason: ', e.reason)  
    elif hasattr(e, 'code'):  
        print('The server couldn/''t fulfill the request.')
        print('Error code: ', e.code)  
else:  
    print("good!")  
    print(response.read().decode("utf8"))  