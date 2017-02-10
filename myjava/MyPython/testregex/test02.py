'''
Created on 2016年8月26日
match只能顺着匹配，
@author: y35chen
'''
import re
pattern = re.compile(r'hello')
result1 = re.match(pattern, 'hello')
result2 = re.match(pattern, 'hello00 CQC')
result3 = re.match(pattern, 'helo CQC!')
result4 = re.match(pattern, 'hello CQC!')
result5 = re.match(pattern, 'CQC!hello ')

if result1:
    print(result1.group())
else:
    print('1 match fail')
    
if result2:
    print(result2.group())
else:
    print('2 match fail')
    
if result3:
    print(result3.group())
else:
    print('3 match fail')
    
if result4:
    print(result4.group())
else:
    print('4 match fail')
    
    
if result5:
    print(result5.group())
else:
    print('5 match fail')