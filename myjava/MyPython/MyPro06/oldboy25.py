'''
Created on 2016年11月16日

@author: y35chen
'''
#!/usr/bin/env python
#_*_coding:utf-8_*_
'''
a = '8*8'
print(eval(a))

temp = 'mysqlserverhelper'
func = 'count'

model = __import__(temp)
Function = getattr(model, func)
print(Function())


import random
print(random.random())
print(random.randint(1,10))
print(random.randrange(1,4))

#temp  =random.randint(65,90)
#print(chr(temp))
code = [] #列表
for i in range(6):
    if i == random.randint(1,9):
        code.append(str(random.randint(1,9)))
    else:
        temp = random.randint(65,90)
        code.append(chr(temp))
print(''.join(code))#列表格式化成字符串,遍历的时候需要每次单独开辟空间，join只需要开辟一次
'''
import hashlib
hashmd5 = hashlib.md5()
hashmd5.update('candy'.encode('utf-8'))
print(hashmd5.hexdigest())
print(hashmd5.digest())