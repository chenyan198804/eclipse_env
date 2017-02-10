'''
Created on 2016年7月8日

@author: y35chen
'''
shoppinglist = ['apple','mango','carrot','banana']
name = 'swaroop'
#Indexing or 'Subscription' Operation 
print('Item 0 is',shoppinglist[0])
print('Item 1 is',shoppinglist[1])
print('Item 2 is',shoppinglist[2])
print('Item 3 is',shoppinglist[3])
print('Item -1 is',shoppinglist[-1])
print('Item -2 is',shoppinglist[-2])
print('CHaracter 0 is',name[0])

#Slicing on List
print('Item 1 to 3 is',shoppinglist[1:3])
print('Item 2 to end is',shoppinglist[2:])
print('Item 1 to -1 is',shoppinglist[1:-1])
print('Item start to end is',shoppinglist[:])
print(shoppinglist[::1])
print(shoppinglist[::2])
print(shoppinglist[::3])
print(shoppinglist[::-1])
