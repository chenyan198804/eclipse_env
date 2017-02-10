#!/usr/bin/env python
#_*_coding:utf-8_*_

from Person import Person
class Choice(object):

    def __init__(self):
        pass
    
    def choice1(self):
        John = Person('Jonh',24,'male','Student',1000,'basketball')
        
        print(
              '''
              **************************************************
              ****    Please select your work:             *****
              ****    0. Network Administrator:800 RMB     *****
              ****    1. Restaurant waiter: 500 RMB        *****
              **************************************************
              '''
              )
        
        number = input('Choose you selection now:(0 or 1)')
        if (int(number)):
            print('{0} choose to be a Restaurant waiter and earns 500 RMB a month'.format(John.name))
        else:
            print('{0} choose to be a Network Administrator and earns 800 RMB a month'.format(John.name))   
            
            
    def choice2(self):
        John = Person('Jonh',24,'male','IT engineer',100000,'bar')
        Liz = Person('Liz',24,'female','Student',3000,'dance')
        
        print(
              '''
              **************************************************
              ****        Please select your choise:       *****
              ****            0. forgive                   *****
              ****            1. Never forgive             *****
              **************************************************
              '''
              )
        number = input('Choose you selection now:(0 or 1)')
        if (int(number)):
            print('{0} and {1} sadly missed each other'.format(John.name,Liz.name))
        else:
            print('{0} and {1} have a happy ending'.format(John.name,Liz.name)) 