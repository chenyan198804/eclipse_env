import re

fp1 = open('D:/myjava/MyPython/hello.txt','r')
fp2 = open('D:/myjava/MyPython/hello.txt','w')
for s in fp1.readlines():
    fp2.write(s.replace("hello","scvt"))