'''
Created on 2016年8月31日

@author: y35chen
'''
'''
# encoding:UTF-8
import re
pattern = re.compile(r'hello')
match = pattern.match('hello world')
if match:
    print(match.group())


m = re.match(r'hello','hello world')
print(m.group())
a = re.compile(r""""\d #the integral part
               \.      #the decimal point
               \d *    #some fractional digits""",re.X)
b = re.compile(r"\d+\.\d*")
'''

import re
p = re.compile(r'(\w+) (\w+)(?P<sign>.*)',re.DOTALL)

print("p.pattern:",p.pattern)
print("p.flags:",p.flags)
print("p.groups:",p.groups)
print("p.groupindex:",p.groupindex)