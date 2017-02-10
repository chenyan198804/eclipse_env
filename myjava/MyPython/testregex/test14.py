'''
Created on 2016年9月5日

@author: y35chen
'''
import copy

a = [1,2,3,4,'a','b','c']
b = a 
print(b)
print(id(a))
print(id(b))
a.append('d')
print(a)
print(b)
print(id(a))
print(id(b))
b.append('e')
print(a)
print(b)
print(id(a))
print(id(b))

a = [1,2,3,['a','b','c']]
b = a 
c = copy.copy(a)
print(b)
print(c)
print(id(a))
print(id(b))
print(id(c))
a.append('d')
print(a)
print(b)
print(c)

print(id(a[3]))
print(id(c[3]))

a[3].append('d')
print(a)
print(b)
print(c)

a = [1,2,3,['a','b','c']]
d = copy.deepcopy(a)
a.append('e')
a[3].append('x')
print(a)
print(d)
print(id(a))
print(id(d))
print(id(a[3]))
print(id(d[3]))


