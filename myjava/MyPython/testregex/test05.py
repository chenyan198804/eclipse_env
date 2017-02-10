'''
Created on 2016年8月26日

@author: y35chen
'''
import re
pattern = re.compile(r'\d+')
print(re.findall(pattern, 'one1two2three3four4five5'))
