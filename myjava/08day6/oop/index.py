#!/usr/bin/env python
#_*_coding:utf-8_*_

class Foo(object):
    def __init__(self):
        print('init')
    def __call__(self):
        return('call')
    
foo = Foo()
foo()