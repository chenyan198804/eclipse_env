'''
Created on 2016年7月8日

@author: y35chen
'''
#!/usr/bin/python
#Filename:using_list.py
shoplist = ['apple','mango','carrot','banana']

print('I have',len(shoplist),'items to purchase')

print('These items are:','\t')

for item in shoplist:
    print(item,'\t')

print('\nI also have to buy rice')
shoplist.append('rice')
print('My shopping list is now ',shoplist)
print('I will sort my shoplist')
shoplist.sort(key=None, reverse=False)
print('Sorted shopping list is', shoplist)
print('The first item i will buy is', shoplist[0])
olditem =shoplist[0]
del shoplist[0]
print('I bought the ', olditem)
print('My shopping list is now', shoplist)

