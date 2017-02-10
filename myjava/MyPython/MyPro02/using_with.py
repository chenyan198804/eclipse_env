'''
Created on 2016年7月15日

@author: y35chen
'''
#!/usr/bin/python 
#Filename : using_with.py 

with open("poem.txt") as f:
    for line in f:
        print(line)
        