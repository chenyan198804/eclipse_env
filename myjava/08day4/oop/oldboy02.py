#!/usr/bin/env python
#_*_coding:utf-8_*_

class Father(object):
    def __init__(self):
        self.Fname = 'fff'
        print('father.__init__')
        
class Son(Father):
    def __init__(self):
        self.sname = 'sss'
        print('son.__init__')
        super(Son,self).__init__()
        
s = Son()
'''
class Father():
    def __init__(self):
        self.Fname = 'fff'
        print('father.__init__')
        
class Son(Father):
    def __init__(self):
        self.sname = 'sss'
        print('son.__init__')
        Father.__init__(self)
        
s = Son()
'''