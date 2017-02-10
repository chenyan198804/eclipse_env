'''
Created on 2016年10月20日

@author: y35chen
'''
file = open('test.txt','r')
for line in file.readlines():
    user,passward = line.strip('\n').split(' ')
    print('user',user)
    print('password',passward)