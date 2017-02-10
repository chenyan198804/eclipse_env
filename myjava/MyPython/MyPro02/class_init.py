'''
Created on 2016年7月13日

@author: y35chen
'''
class Person:
    def __init__(self,name):
        self.name = name
    def sayhi(self):
        print('hello, my name is ',self.name)
        
p = Person('Swaroop')
p.sayhi()