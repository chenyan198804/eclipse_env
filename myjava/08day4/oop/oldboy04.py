#!/usr/bin/env python
#_*_coding:utf-8_*_


def Validate(name,pwd):
    if name == 'alex' and pwd == '123':
        return True
    else:
        return False
    
try:
    res = Validate('alex', '456')
    if res:
        print('login success')
    else:
        raise Exception('login Failure')
except Exception as e:
    print(e)