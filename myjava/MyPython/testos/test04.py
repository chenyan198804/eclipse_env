'''
Created on 2016年9月6日

@author: y35chen
'''
import os
g = os.walk('testdir')
print(g.__next__())
print(g.__next__())
print(g.__next__())
print(g.__next__())
print(g.__next__())
print(os.walk('testdir'))

