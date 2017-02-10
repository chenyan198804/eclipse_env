'''
Created on 2016年8月26日

@author: y35chen
'''
#-*- coding:utf-8 -*-
from urllib.request import Request
import urllib.request

def httpRequest(url,proxy = None):
    try:
        ret = None
        SockFile = None
        request = Request(url)
        request.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)')
        request.add_header('Pragma', 'no-cache')
        if proxy:
            request.set_proxy(proxy,'http')
        opener = urllib.request.build_opener()
        SockFile = opener.open(request)
        ret = SockFile.read().decode('utf-8')
    finally:
        if SockFile:
            SockFile.close()
    
    return ret       
if __name__=='__main__':  
    response = httpRequest('http://www.baidu.com', '10.144.1.10:8080' )
    print(response)