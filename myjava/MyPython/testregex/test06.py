'''
Created on 2016年8月26日

@author: y35chen
'''
import re
pattern = re.compile(r'\d+')
for m in re.finditer(pattern, 'one1two2three3four4'):
    print(m.group())

p = re.compile(r'\d+')
print(p.split('one1two2three3four4'))

print(p.findall('one1two2three3four4'))