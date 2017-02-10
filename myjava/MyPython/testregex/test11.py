'''
Created on 2016年9月5日

@author: y35chen
'''

import re

rs = r'c..t'
r = re.sub(rs,'python','csvt,cact,ccccc,cltt')
print(r)

s = '123+456*789'
print(re.split(r'[\+\-\*]', s))

r1 = r"csvt.net"
print(re.findall(r1, 'csvtxnet'))
print(re.findall(r1, 'csvt\n.net'),re.S)
print(re.findall(r1, 'csvt\tnet'),re.S)

s2 = """
    hello csvt_re
    hello 
    csvt here
    """
r2 = r"csvt"
print(re.findall(r2,s2,re.M))


tel = r"""
\d{3,4}
-?
\d{8}
"""
print(re.findall(tel, '010-12345678', re.X))


email = r"\w{3}@\w+(\.com|\.cn)"
print(re.match(email,'zzz@csvt.com'))
print(re.match(email,'zzz@csvt.cn'))
print(re.match(email,'zzz@csvt.org'))

print(re.findall(email, 'zzz@csvt.com'))




