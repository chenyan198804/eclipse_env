'''
Created on 2016年9月2日

@author: y35chen
'''
'''
class Test:
    def prt(self):
        print(self)
        print(self.__class__)
 
t = Test()
t.prt()

class Parent:
    def pprt(self):
        print(self)
 
class Child(Parent):
    def cprt(self):
        print(self)
c = Child()
c.cprt()
c.pprt()
p = Parent()
p.pprt()
'''

class Desc:
    def __get__(self, ins, cls):
        print('self in Desc: %s ' % self )
        print(self, ins, cls)
class Test:
    x = Desc()
    def prt(self):
        print('self in Test: %s' % self)
t = Test()
t.prt()
t.x