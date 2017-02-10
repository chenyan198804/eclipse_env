'''
Created on 2016年9月2日

@author: y35chen
'''
import re
#r = re.compile(r"^010-\d\d\d\d\d\d\d\d")
r = re.compile(r"^010-\d{8}")
result = re.findall(r, '010-89721912')
print(result)

r1 = re.compile(r"ab*")
result1 = re.findall(r1, 'a')
print(result1)


r2 = re.compile(r"ab+")
result2 = re.findall(r2, 'abb')
print(result2)


r3 = re.compile(r"^010-?\d{8}")
result3 = re.findall(r3, '010-89721912')
print(result3)


r4 = re.compile(r"ab+?")
result4 = re.findall(r4, 'abbbbbb')
print(result4)


r5 = re.compile(r"a{1,3}")
result5 = re.findall(r5, 'aaaaaaa')
print(result5)

r6 = re.compile(r"\d{3,4}-\d{8}")
result6 = re.findall(r6, '010-8972192')
print(r6)
print(result6)

csvt_re = re.compile(r"csvt",re.I)
print(csvt_re.findall("CSvT"))

print(csvt_re.match('csvt hello'))
print(csvt_re.match('hello'))
print(csvt_re.match('hello csvt '))

print(csvt_re.search('csvt hello'))
print(csvt_re.search('hello'))
print(csvt_re.search('hello csvt '))


print(csvt_re.findall('hello csvt hello csvt csvt'))

print(csvt_re.finditer('hello csvt hello csvt csvt'))

x = csvt_re.finditer('hello csvt hello csvt csvt')
