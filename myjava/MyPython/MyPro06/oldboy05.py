'''
Created on 2016年10月20日

@author: y35chen
'''
#!/usr/bin/env python
#_*_coding:utf-8_*_
import sys 
retry_limit = 3
retry_count = 0
account_file = 'accounts.txt'
lock_file = 'account_lock.txt'

while retry_count < retry_limit:
    username = input('username')
    lock_check = open(lock_file)
    
    for line in lock_check.readlines():
        if line==username:
            sys.exit('User %s is locked!' %line)
    
    passward = input('password')
    
    f = open(account_file,'r')
 
    match_flag = False
    for line in f.readlines():        
        user,passwd = line.strip('\n').split()
        if username == user and passward == passwd:
            print('Match'),username
            match_flag = True
            break
        
    f.close()
    if match_flag == False:
        print('User unmatch')
        retry_count += 1
        
    else:
        print('Welcome')
        break
        
else:
    print('Your account is locked')
    f = open(lock_file,'w+')
    f.write(username)
    f.close
    
    
        
        