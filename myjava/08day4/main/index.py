#!/usr/bin/env python
#_*_coding:utf-8_*_
str1 = 'demo'
str2 = 'Foo'

module = __import__(str1)
func = getattr(module,str2)

func()