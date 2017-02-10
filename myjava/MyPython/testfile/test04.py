'''
Created on 2016年9月5日

@author: y35chen
'''
import re

file = open('D:/myjava/MyPython/hello.txt','r')
count = 0
for s in file.readlines():
    li = re.findall('hello', s)
    #print('li:',li)
    if len(li) > 0:
        count += len(li)
        #print(len(li))
print("search",count,"hello")
file.close()