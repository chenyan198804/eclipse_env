#!/usr/bin/env python
#_*_coding:utf-8_*_

from abc import ABCMeta,abstractclassmethod
class Alert:
    __metaclass__ = ABCMeta
    
    @abstractclassmethod
    def Send(self):pass
    
class Weixin(Alert):
    def __init__(self):
        print('__init__')
        
    def Send(self):
        print('Send.Weixin')
        
f = Weixin()
f.Send()
   
