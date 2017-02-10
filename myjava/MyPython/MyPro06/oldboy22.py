'''
Created on 2016年11月3日

@author: y35chen
'''
from pip._vendor.requests.packages.urllib3.connectionpool import xrange
def foo():
    yield 1
    yield 2
    yield 3 
    yield 4
    yield 5  
re = foo()
print(re)
for item in re:
    print(item)
#print(re)
#print(range(10))
#print(xrange(10))

#for item in xrange(10):
#    print(item)
    
