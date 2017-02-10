#!/usr/bin/env python
#_*_coding:utf-8_*_

import _winreg
key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,r"SOFTWARE\Classes\*\shell",0, _winreg.KEY_ALL_ACCESS )

try:
    i = 0
    while True:

        sub_key = _winreg.EnumKey(key,i)

        print sub_key
        i+=1
except WindowsError:
    print
'''
import _winreg
key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{28D5B8E1-A200-4F4C-949B-01732017BA5F}")
try:
    i = 0
    while True:
        name,value,type = _winreg.EnumValue(key,i)
        print repr(name),value,type
        i+=1
except WindowsError:
    print
'''