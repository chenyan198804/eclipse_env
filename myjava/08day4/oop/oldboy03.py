#!/usr/bin/env python
#_*_coding:utf-8_*_

class A:
    def __init__(self):
        print('This is A')
        
    def save(self):
        print('save method from A')                

class B(A):
    def __init__(self):
        print('This is B')

class C(A):
    def __init__(self):
        print('This is C')
        
    def save(self):
        print('save method from C')
        
        

class D(B,C):
    def __init__(self):
        print('This is D')


c = D()
c.save()


