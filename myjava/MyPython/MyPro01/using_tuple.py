'''
Created on 2016年7月8日

@author: y35chen
'''
#!/usr/bin/python
#Filename:using_tuple.py

zoo = ('python', 'elephant', 'penguin') # remember the parentheses are optional 
print('Number of anaimals in zoos is',len(zoo))

new_zoo = ('mokey','camel',zoo)
print('Number of cages in new zoo is', len(new_zoo))
print('All animals in new zoo are',new_zoo)
print('Animal brought from old zoo is', new_zoo[2])
print('Last animal brought from old zoo is', new_zoo[2][2])
print('Number of animals in new zoo is',len(new_zoo)-1+len(new_zoo[2]))