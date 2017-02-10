#!/usr/bin/env python
#_*_coding:utf-8_*_

class Person(object):
    def __init__(self,name,age,sexuality,work,salary,special):
        self.name = name
        self.age = age
        self.sexuality = sexuality
        self.work = work
        self.salary = salary
        self.special = special
        
    def talk(self,word):
        print("{0}:\"{1}\"".format(self.name,word))