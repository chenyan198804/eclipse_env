'''
Created on 2016年10月21日

@author: y35chen
'''
#!/usr/bin/env python
f = open('test.txt')

for i in f.readlines():
    print(i.strip('\n').split())