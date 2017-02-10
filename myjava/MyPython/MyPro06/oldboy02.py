'''
Created on 2016年10月18日

@author: y35chen
'''


name = input("please input your name:")
age =  input("please input your age:")
job =  input("please input your job:")
salary =  input("please input your salary:")
print(type(name),type(age),type(job),type(salary))
print(
'''
Pernal information of %s:
                        Name:%s
                        Age:%s
                        Job:%s
                        Salary:%s
--------------------------------------
'''%(name,name,age,job,salary)
)
