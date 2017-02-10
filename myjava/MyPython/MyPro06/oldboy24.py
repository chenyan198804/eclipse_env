'''
Created on 2016年11月14日

@author: y35chen
'''

temp = lambda x,y:x+y 
print(temp(4,4))

a = [x*2 for x in range(10)]
print(a)

b = map(lambda x:x**2,range(10))
print(b)

print(divmod(5,5))

print(max(11,2,33,111))
print(min(11,2,33,111))

print(pow(2,10))

print(chr(65))
print(chr(66))
print(chr(67))

print(ord('A'))

print(hex(2))
print(bin(2))
print(oct(2))

list = ['手表','汽车','房子']
for item in list:
    print(item)
    
for item in enumerate(list,1):
    print(item)

s = 'i am {0}'
print(s.format('alex'))



print(all([1,2,3,4]))
print(all([1,2,3,0]))
print(all((1,2,3,0)))
print(all({1,2,3,0}))
print(any([1,2,3,4]))
print(any([1,2,3,0]))
print(any((1,2,3,0)))
print(any({1,2,3,0}))

print(bool(''))
print(bool(None))

def Function(args):
    print(args)
    
Function('alex')

#def f(x, y): return (x, y)  
l1 = [ 0, 1, 2, 3, 4, 5, 6 ]  
l2 = [ 'Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat' ]  
#a = map(f,l1,l2)


def foo(args):
    if args < 22:
        return True
    else:
        return False
li = [11,22,33]
f1 = filter(foo,li)
print(f1.__next__())


from functools import reduce
l1 = [ 0, 1, 2, 3, 4, 5, 6 ]
print('reduce',reduce(lambda x,y:x+y, l1))

x = [1,2,3]
y = [4,5,6]
z = [4,5,6]
a = zip(x,y,z)
print(a.__next__())
print(a.__next__())
print(a.__next__())


