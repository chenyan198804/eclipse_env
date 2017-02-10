'''
Created on 2016年10月27日

@author: y35chen
'''

name_info = {
             'name':'Jacky',
             'age':29,
             'job':'Enginner',
             'salary':3000
             }


print(name_info['name'])
name_info['job']='IT'
print(name_info)
name_info.pop('job')
print(name_info)
name_info.popitem()
print(name_info)

print(name_info.items())


for i in name_info:   #效率高
    print(i,name_info[i])
print('*********************')
for k,v in name_info.items(): #效率低
    print(k,v)
print('*********************')

print(name_info.get('age'))
print('*********************')
name_info.setdefault('stuID',1123)
print(name_info)
name_info.setdefault('stuID',33)
print(name_info)
print('*********************')
a = {'job':'Engineer','addr':'Beijing'}
name_info.update(a)
print(name_info)
print('*********************')   
    
info2 = name_info
name_info['job'] = 'HR'
print(info2)
print(name_info)

info2['job'] = 'Sales'
print(info2)
print(name_info)
print(id(info2))
print(id(name_info))

print(id(info2['job']))
print(id(info2['age']))
print(id(name_info['job']))

print('*********************')   

info3 = name_info.copy()  #浅copy
name_info['Sex']='M'
name_info['age']='80'
name_info['ex_list']=['Coral','Erion']
info3['nationality']='Chinese'
print(name_info)
print(info3)

print('*********************')
info4 = name_info.copy()
name_info['addr']='Hongkou'
name_info['ex_list'].append('Wutenglan')
print('name_info',name_info)
print('info4',info4)
print('*********************')


import copy 
info5 = copy.deepcopy(name_info)#深copy
name_info['ex_list'][2] = 'LongZeluola'
print('name_info',name_info)
print('info5',info5)