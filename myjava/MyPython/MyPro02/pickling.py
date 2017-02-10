'''
Created on 2016年7月14日

@author: y35chen
'''
#!/usr/bin/python
#Filename : pickling.py 

import pickle
# the name of the file where we will store the object 
shoplistfile = 'shoplist.data'
#the list of things to buy
shoplist = ['apple','mango','carrot']

#Write to the File
f = open(shoplistfile, 'wb')
pickle.dump(shoplist,f) 
#dump the object to a  File
f.close()

del shoplist

#read back from the storage
f = open(shoplistfile, 'rb')
storedlist = pickle.load(f)
#load object from the File

print(storedlist)