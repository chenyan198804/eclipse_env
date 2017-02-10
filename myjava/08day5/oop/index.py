#!/usr/bin/env python
#_*_coding:utf-8_*_

class Person(object):
    #静态字段，属于类
    m = 'String'
    def __init__(self,name,gene,weight,clothes):
        self.Name = name
        self.__Gene = gene
        if name != 'alex':
            self.Gender = '男'
        self.Weight =weight
        self.Age = None
        self.__clothes = clothes
    
    def talk(self):
        print('xxx')
        
    def fight(self,weight):
        if self.Weight > weight:
            print('fight')
        else:
            print('no')
            
    @property
    def Gene(self):
        return self.__Gene
    
    @property
    def Clothes(self):
        return self.__clothes
    
    @Clothes.setter 
    def Clothes(self,value):
        self.__clothes = value
               
            
P1 = Person('n1','a',190,'CC')
P2 = Person('n2','aa',100,'CC')
P1.Age = 18

P2.fight(P1.Weight)
#获取的只是字段
data = P2.__dict__

print(data)

print(Person.m)
#print(dir(P2))