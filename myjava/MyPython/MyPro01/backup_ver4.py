'''
Created on 2016年7月11日

@author: y35chen
'''
#!/usr/bin/python
#Filename:backup_ver2.py 
import zipfile,os
import time


#1. the files and directories to be backed up are  specified in a List
startdir = "D:\\test"
#Notice  we had  to use double quotes inside the string for names with space in it
#2. The backup must stored in  a main backup Directory
target_dir = 'D:\\Backup'
#Remember to change this  to what you will be Using
#3.The files are backup into a zip file
#4.The name of the zip archive is the current date and time
today = target_dir + os.sep + time.strftime('%Y%m%d')
#the current time is the name of the zip archive
now = time.strftime('%H%M%S')
#Take a comment from the user to create the name of zip file
comment = input('Enter a comment -->')

if len(comment) == 0:
    target = today + os.sep + now + '.zip'
    name = now + '.zip'
else:
    target = today + os.sep + now + '_' + comment.replace(' ', '_') + '.zip'
    name = now + '_' + comment.replace(' ', '_') + '.zip'
    
print(today)

print(target)

#Create the subdirectory if it isn't already there
if not os.path.exists(today):
    os.mkdir(today) #make directory
    print('Sucessfully create directory', today)
    
f = zipfile.ZipFile(name+'.zip','w',zipfile.ZIP_DEFLATED)
help(zipfile.ZipFile)
#for dirpath, dirnames,filenames in os.walk(startdir):
#    for filename in filenames:
#        f.write(os.path.join(dirpath,filename))
#        zip.write(os.path.join(startdir),os.path.join(startdir).replace(startdir+os.sep,''))
f.close()

