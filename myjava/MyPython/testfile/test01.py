'''
Created on 2016年9月5日

@author: y35chen
'''
#import os
test = '''
hello world\nthis is new\n
'''
#print(os.path.exists('D:/myjava/MyPython/test.txt'))

#file = open('D:/myjava/MyPython/test.txt')
#file.write(test)
#s1 = file.read()
file = open('D:/myjava/MyPython/test.txt')
while True:
    line1 = file.readlines()
    #line2 = file.readline()
    if len(line1) == 0:
        break
    print(line1)
    #print(line2)
#for i in open('D:/myjava/MyPython/test.txt'):
#    print(i)

