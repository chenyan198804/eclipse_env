'''
Created on 2016年11月18日

@author: y35chen
'''
#!/usr/bin/env python
#_*_coding:utf-8_*_
import time 

print(time.time())
print(time.mktime(time.localtime()))
print('************************')
print(time.gmtime())
print(time.localtime())
print(time.strptime('2016-11-11','%Y-%m-%d'))
print('************************')
print(time.strftime('%Y-%m-%d %H:%M:%S'))
print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime()))
print(time.asctime())
print(time.asctime(time.localtime()))
print(time.ctime(time.time()))
print(time.strftime('%a %b %d',time.localtime(time.time())))
print(time.strftime('%c',time.localtime(time.time())))
print(time.strftime('%I %p',time.localtime(time.time())))
print(time.strftime('%Y-%m-%d %H:%M:%S %Z',time.localtime(time.time())))

