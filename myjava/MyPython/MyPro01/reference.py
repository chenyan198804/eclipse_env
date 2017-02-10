'''
Created on 2016年7月11日

@author: y35chen
'''
#!/usr/bin/python
# Filename:reference.py
print('Simple Assignment')
shoplist = ['appple','mango','carrot','banana']
mylist = shoplist
#mylist is just another name pointing to the same object
del shoplist[0]
print('shoplist is ',shoplist)
print('mylist is',mylist)
#notice both shoplist and mylist print the same list with 'apple'
print('Copy by making a full slice')
mylist = shoplist[:]
del mylist[0]
print('shoplist is ',shoplist)
print('mylist is',mylist)

