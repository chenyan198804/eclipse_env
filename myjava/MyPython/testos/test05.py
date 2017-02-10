'''
Created on 2016年9月6日

@author: y35chen
'''
try:
    #open('hello.txt')
    print(hello)
except IOError as msg:
    print("IOError")      
except NameError as msg:
    print("NameError")
