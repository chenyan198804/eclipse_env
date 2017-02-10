'''
Created on 2016年11月16日

@author: y35chen
'''
#!/usr/bin/env python
#_*_coding:utf-8_*_
import pickle

li = ['alex','11','22','ok']
dumped = pickle.dumps(li)
print(type(li))
print(dumped)
print(type(dumped))

loaded = pickle.loads(dumped)
print(loaded)
print(type(loaded))

with open('D:/temp_pickle.txt','wb') as f:  
        #dump()函数接受一个可序列化的Python数据结构  
        pickle.dump(li,f)
        print('success')
with open('D:/temp_pickle.txt','rb') as f:  
        user=pickle.load(f) 
        print(user) 
