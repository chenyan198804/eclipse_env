'''
Created on 2016年11月3日

@author: y35chen
'''
from cffi.backend_ctypes import xrange
def show(**kargs):
    for item in kargs.items():
        print(item)
user_dict = {'k1':123,'k2':456}
show(**user_dict)

for item in xrange(10):
    print(item)