'''
Created on 2016年10月24日

@author: y35chen
'''
a = ['1','2','3','4','1','2','3','4','2','2','2','2']
pos = 0
for i in range(a.count('2')):
    if pos == 0:
        pos = a.index('2')
    else:
        pos = a.index('2',pos+1 )
    print(pos)
    
    
print(help(a.index))