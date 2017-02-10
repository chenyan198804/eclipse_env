'''
Created on 2016年9月6日

@author: y35chen
'''
#!/usr/bin/python
#coding:utf-8

import os

def dirList(path):
    filelist = os.listdir(path)
    allfile = []
    for filename in filelist:
        filepath =  os.path.join(path,filename)
        #递归调用
        if os.path.isdir(filepath):
            dirList(filepath)
        allfile.append(filepath)
        print(filepath)

allfile = dirList('testdir')
