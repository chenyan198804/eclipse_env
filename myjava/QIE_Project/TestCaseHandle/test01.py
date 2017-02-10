#!/usr/bin/env python
#_*_coding:utf-8_*_

import _winreg
from _winreg import KEY_ALL_ACCESS 

with _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\*\shell") as key:
    print key

    newKey = _winreg.CreateKeyEx(key,"YNote",0,KEY_ALL_ACCESS)
    
    sub_key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,r"SOFTWARE\Classes\*\shell\YNote")
    newsubKey = _winreg.CreateKey(sub_key,"command")
    
    _winreg.SetValue(newsubKey,"(Default)",1,"\"C:\Program Files (x86)\Youdao\YoudaoNote\YoudaoNote.exe\" \"%1\"")
    
