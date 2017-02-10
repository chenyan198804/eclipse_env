#!/usr/bin/env python
#_*_coding:utf-8_*_
import _winreg 
key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER,r"Software\Microsoft\Windows\CurrentVersion\Explorer")
newKey = _winreg.CreateKeyEx(key,"MyNewkey",0,_winreg.KEY_ALL_ACCESS)
try:
    i = 0
    while True:
        Enumkey = _winreg.EnumKey(key,i)
        print Enumkey
        i+=1
except WindowsError:
    print
sub_key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER,r"Software\Microsoft\Windows\CurrentVersion\Explorer\MyNewkey")
newsubKey = _winreg.CreateKey(sub_key,"command")

        #_winreg.SetValueEx(newsubKey,"(Default)",0,1,"\"C:\Python27\python.exe\" \"%1\"")
