'''
Created on 2016年7月13日

@author: y35chen
'''
#!/usr/bin/python
#Filename: objvar.py 
class Robot:
    '''Represents a robot, with a name.'''
    #A class variable, counting the number of robots
    population = 0   #population 是属于Robot类的对象
    
    def __init__(self,name):
        '''Initializes the data.'''
        self.name = name            #name 是属于对象（用self给其赋值），因此是对象的变量
        print('(Initialize {0})'.format(self.name))
        
        #when this person is created, the robot add to population
        Robot.population += 1
        
    def __del__(self):
        '''I am dying'''
        print('{0} is being destoryed!'.format(self.name))
        Robot.population -= 1
        
    def sayHi(self):
        '''Greeting by robot
        Year, they can do that 
        '''
        print('Greetings, my master call me {0}'.format(self.name))
        
    def howMany():
        '''Prints the current population.'''
        print('We have {0:d} robots'.format(Robot.population) )
    howMany = staticmethod(howMany)
    
droid1 = Robot('R2-D2')
droid1.sayHi()
Robot.howMany()

    
droid2 = Robot('C-3P0')
droid2.sayHi()
Robot.howMany()

print('\nRobots can do some work here.\n')
print("Robot have finished their work, so let's destory them")

del droid1
del droid2

Robot.howMany()

    
        