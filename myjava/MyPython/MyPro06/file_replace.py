'''
Created on 2016年10月24日

@author: y35chen
'''
#_*_coding:utf-8_*_
      
import sys, os
if len(sys.argv) <= 4:
    print("usage:./file_replace.py old_text new_text filename")

old_text = sys.argv[1]
new_text = sys.argv[2]
file_name = sys.argv[3]


f = open(file_name,'rb')
new_file = open('.%s.bak'%file_name,'wb')  #new file for writing
for line in f.xreadlines(): #循环这个源文件loop old file and replace the old text to new text
    print(line.replace(old_text,new_text))
    new_file.write(line.replace(old_text,new_text)) #write replaced line into new file
    
f.close()
new_file.close()


if '--bak' in sys.argv:
    os.rename(file_name,'.%s.bak2' %file_name) #unchanged
    os.rename('.%s.bak' %file_name,file_name)  #changed
else:
    os.rename('.%s.bak' %file_name,file_name)  #replace old file


