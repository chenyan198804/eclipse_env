'''
Created on 2016年9月6日

@author: y35chen
'''

import os.path
rootdir = "d:\Backup"

for parent,dirnames,filenames in os.walk(rootdir):
    for dirname in dirnames:
        print("parent is :",parent)
        print("dirname is :",dirname)
        
    for filename in filenames:
        print("parent is :",parent)
        print("filename is :",filename)
        print("the full name of file is:",os.path.join(parent,filename))