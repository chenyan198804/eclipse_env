#!/usr/bin/env python
#_*_coding:utf-8_*_

from backend import account

#输入：xxx/xxx
#account/login
data = input('请输入地址：')
array = data.split('/')
if data == 'account/login':
    account.login()
elif data == 'account/logout':
    account.logout()

#主流的web框架
data = input('请输入地址：')
array = data.split('/')
#array[0] = account
try:
    userspace = __import__('backend.'+array[0])
    model = getattr(userspace, array[0])
    func = getattr(model, array[1])
    func()
except ImportError as e:
    print('1',e)
    print('self_define 404')
except AttributeError as e:
    print('2',e)
    print('self_define 404')
    
except Exception as e:
    print('3',e)
    print('self_define 404')
else:
    print('没有错误')
    
finally:
    print('无论如何都执行')

    
class MyException(Exception):
    def __init__(self,msg):
        self.error = msg
        
    def __str__(self,*args,**kwargs):
        return self.error

obj = MyException('错误')
print(obj)
#主动触发错误
raise MyException('自定义错误')
    