#!/usr/bin/env python
#_*_coding:utf-8_*_
from threading import Thread
import time 
def Foo(arg,v):
    for item in range(10):
        print(item)
        time.sleep(1)
    
print('before')   
t1 = Thread(target=Foo,args=(1,11))
#t1.setDaemon(True)

t1.start()

t1.join(3)

print(t1.getName())
print('************',t1.isDaemon())


print('after')   
print('after')   
print('after')   
print('after')   
print('after end')   
time.sleep(5)
