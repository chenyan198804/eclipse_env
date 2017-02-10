'''
Created on 2016年10月24日

@author: y35chen
'''
'''
name_list = ['Alex','Jack','Candy']
name_list.append('Eric')
print(name_list)
name_list.insert(1, 'Lucy')
print(name_list)
name_list.remove('Eric')
print(name_list)
name_list.append('Jack')
print(name_list)
print(name_list.count('Jack'))

print(name_list.index('Jack'))
name_list.append('!')
name_list.append('#')
name_list.sort()
print(name_list)


name_list.extend('abcd')
print(name_list)

name_list.extend('12345')
print(name_list)

print(name_list[2:5])

print(name_list[-5:])

print(name_list[name_list.index('2'):name_list.index('2')+4])


name_list.extend('1234')

print(name_list.count('2'))
 '''
name_list = ['1','2','3','4','1','2','3','4','2','2','2','2']
first_pos = 0
for i in range(name_list.count('2')):    
    new_list = name_list[first_pos:]
    next_pos = new_list.index('2')+1
    print('Find position:',first_pos+ new_list.index('2'))
    first_pos += next_pos



