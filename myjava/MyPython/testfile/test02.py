'''
Created on 2016年9月5日

@author: y35chen
'''
l = ['one\n','two\n','three\n']
f1 = open('D:/myjava/MyPython/test01.txt','a+')
f1.writelines(l)

l1 = f1.read()
print('l1:',l1)
#移动到文件开头
f1.seek(0,0)
l2 = f1.read()
print('l2:',l2)

f1.seek(0,2)
l3 = f1.read()
print('l3:',l3)
f1.close()