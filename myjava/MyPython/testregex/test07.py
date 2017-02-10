'''
Created on 2016年8月26日

@author: y35chen
'''
import re
pattern = re.compile(r'(\w+) (\w+)')
s = 'i say,hello world!'
print(re.sub(pattern,r'\2 \1',s))
def func(m):
    return m.group(1).title()+' '+m.group(2).title()
print(re.sub(pattern,func,s))