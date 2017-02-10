'''
Created on 2016年9月6日

@author: y35chen
'''
import os
#os.mkdir('testos')
#os.makedirs('a/b/c')
#os.rmdir('testos')
#os.removedirs('a/b/c')
print(os.listdir('/'))
print(os.getcwd())
os.chdir('/myjava')
print(os.listdir('.'))