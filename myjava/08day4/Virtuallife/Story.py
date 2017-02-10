#!/usr/bin/env python
#_*_coding:utf-8_*_
from Person import Person
from Car import Car
from School import School
import time

class Story(object):
    def __init__(self):
        pass   
            
    def wait(self,seconds):
        time.sleep(seconds)
        
    def introduce(self):
        John = Person('Jonh',20,'male','Student',0,'basketball')
        Liz = Person('Liz',20,'female','Student',0,'dance')
        print(
        '''
        ======================Story Background============================
        ''')
        print('{0} and {1} are classmates of senior high school,they love each other!'.format(John.name,Liz.name))
    
    def Begining(self):
        John = Person('Jonh',20,'male','Student',0,'basketball')
        Liz = Person('Liz',20,'female','Student',0,'dance')
        print(
        '''
        ===========================Story Begin=============================
        '''
        )
        Liz.talk('I was admitted to Beijing City University')
        s.wait(2)
        John.talk('I was not,but I\'ll go to Beijing and earn the fee of schooling for you')
        s.wait(2)
        Liz.talk('It\'s so nice of you,thanks')
        s.wait(2)
        John.talk('I love you')
        
    def Transmission(self):
        print(
        '''
        =========================Few years later============================
        Many things happens this years,but they are still together,love each other.
        '''
        )
        
    def interview(self):
        print(
        '''
        ======================Interview after graduate======================
        '''
        )
        Peter = Person('Peter',30,'male','manager',10000,'bar')
        Liz = Person('Liz',24,'female','Student',3000,'dance')
        John = Person('Jonh',20,'male','Student',800,'basketball')
        Liz.talk('Hi,my name is Liz,here is my resume')
        s.wait(2)
        Peter.talk('Nice!You are hired, and by the way, May I drive you home?')
        Liz.talk('Thanks!')
        car = Car('Ferrari')
        print('\n')
        print('{0} driver {1} home with {2}'.format(Peter.name,Liz.name,car.name))
        s.wait(2)
        
        print('{0} kissed {1},then {1} runs home'.format(Peter.name,Liz.name))
        print('Finnaly{0} and {1} was together and {2} was sad'.format(Peter.name,Liz.name,John.name))
        print('\n')
        
    def Fightingyears(self):
        print(
        '''
        ===========================Fighting years=========================
        '''
        )
        Liz = Person('Liz',24,'female','Student',3000,'dance')
        John = Person('Jonh',20,'male','Student',800,'basketball')
        school = School('Python trainning Lab')
        print('{0} decide to persume {1} back, and he goes to school called {2}'.format(John.name,Liz.name,school.name))
        
        
    def endline(self):
        print(
        '''
        ===============================Ending==============================
        '''
        )
        John = Person('Jonh',24,'male','IT engineer',100000,'bar')
        Liz = Person('Liz',24,'female','Student',3000,'dance')
        print('{0} learn python,then become a {1},earns {2} a month'.format(John.name,John.work,John.salary))
        s.wait(2)
        print('{0} buys car and house'.format(John.name))
        s.wait(2)
        print('{0} and {1} meet one day'.format(John.name,Liz.name))
        s.wait(2)
        print('{0} said: {1} could you forgive the fault i have made?'.format(Liz.name,John.name))
        
s = Story()
