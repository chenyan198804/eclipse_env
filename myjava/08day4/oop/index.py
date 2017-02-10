#!/usr/bin/env python
#_*_coding:utf-8_*_
'''
class Person:
    xue = '血'
    #实例化的动作
    def __init__(self,name,age):
        self.name = name
        self.age = age
        
p1 = Person('Liyang',18)
print(p1.name,p1.age)
p2 = Person('Lisa',16)
print(p2.name,p2.age)
    
'''

class Province(object):
    #静态字段，属于类
    memo = '中国的23省之一'
    #动态字段，属于对象
    def __init__(self,name,capital,leader,flag):
        self.Name = name
        self.Capital = capital
        self.Leader = leader
        
        self.__Thailand = flag
        
    def sports_meet(self):
        print(self.Name + '正在开运动会')    
        
    #动态方法变静态方法
    @staticmethod    
    def Foo():
        print('每个省要带头反腐')
    #把方法变成特性
    @property    
    def Bar(self):
        print(self.Name)
        return 'something'
    
    def show(self):
        print(self.__Thailand)
        
    def __sha(self):
        print('i\'m alex')
        
    def Foo2(self):
        self.__sha()
    #只读   
    @property
    def Thailand(self):
        return self.__Thailand
    
    #可以改
    @Thailand.setter
    def Thailand(self,value):
        self.__Thailand = value
                
        
Japan = Province('日本','大阪','Lily',True)
print(Japan.Thailand)
Japan.Thailand = False
print(Japan.Thailand)
#print('__Thailand',Japan.__Thailand)
#Japan.show()

#Japan.__sha()
#Japan.Foo2()
#Japan._Province__sha
#print(Japan.Thailand)





#hb = Province('??','???','liYang')
#print(hb.Name,hb.Capital,hb.Leader)

#hb.sports_meet()

#print(Province.Foo())

#print(hb.Bar)

#print(Province.memo)
#print(hb.memo)