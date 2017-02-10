#!/usr/bin/env python
#_*_coding:utf-8_*_

class Foo:
    def __init__(self):
        pass
    
    def __del__(self):
        print('删除')
        
    def Go(self):
        print('Go')
        
    def __call__(self):
        print('call')
        
        
f1 = Foo()
f1.Go()
f1()#执行f1的call方法
