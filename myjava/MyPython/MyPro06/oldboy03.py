'''
Created on 2016年10月18日

@author: y35chen
'''

#name = input("please input your name:")
#age =  input("please input your age:")
#job =  raw_input("please input your job:")
#salary =  input("please input your salary:")
real_age =29
for i in range(10):
    age = input('age:')
    if int(age) > 29:
        print('Think smaller')
    elif int(age) == 29:
        print('You are right')
        break
    elif int(age) < 29:
        print('Think bigger')
    print('You still got %s shots!'%(9-i))

#if int(age) > 40:
#    msg = 'You are too old'
#elif age > 30:
#    msg = 'You still have few years to fight'
#else:
#    msg = ' You are young'
#print(type(age),type(age),type(job),type(salary))
#print(
'''
Pernal information of %s:
                        Name:%s
                        Age:%s
                        Job:%s
                        Salary:%s
--------------------------------------
%s
'''#%(name,name,age,job,salary,msg)
#)


