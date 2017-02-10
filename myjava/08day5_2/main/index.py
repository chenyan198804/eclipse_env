#!/usr/bin/env python
#_*_coding:utf-8_*_
from model.admin import Admin
def main():
    user = input('username:')
    pwd = input('password:') 
    admin = Admin()

    result = admin.CheckValidate(user, pwd)
    print('user check result:',result)
    
    if not result:
        print('Wrong username or password')
    else:
        print('login success')

if __name__ == '__main__':
    main()
