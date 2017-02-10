'''
Created on 2016年10月27日

@author: y35chen
'''

      
contact_list = 'contact_list.txt'
print(help(input()))
match_flag = 0
inp = input('match_item')
f = open(contact_list,'r')
for line in f.readlines():
    info = line.strip('\n').split()
    if info[0] == inp:
        print(info[1])
        
        
        
