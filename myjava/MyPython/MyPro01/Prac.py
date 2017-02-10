'''
Created on 2016年7月7日

@author: y35chen
'''
import sys
print(dir(sys))
print(dir())
a = 5
print(dir())
del a
print(dir())

import mymodule
mymodule.sayhi();
print('Version',mymodule.__version__)

from mymodule import sayhi,__version__
sayhi()
print('Version',__version__)

