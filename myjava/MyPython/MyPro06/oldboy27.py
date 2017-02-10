#!/usr/bin/env python
#_*_coding:utf-8_*_

import pickle  
   
#序列化  
def dump_pickle():  
    user={}  
    user['id']=1 
    user['name']='tanweijie' 
    user['email']='tanweijie@outlook.com' 
    user['sex']='boy' 
    print(user)
   
    #with保证自动关闭文件  
    #设置文件模式为'wb'来以二进制写模式打开文件  
    with open('D:/temp_pickle.txt','wb') as f:  
        #dump()函数接受一个可序列化的Python数据结构  
        pickle.dump(user,f)  
        print('success')  
   
#反序列化  
def load_pickle():  
    with open('D:/temp_pickle.txt','rb') as f:  
        user=pickle.load(f)  
    #user变量是一个字典      
    print(user)  
    
dump_pickle()
load_pickle()