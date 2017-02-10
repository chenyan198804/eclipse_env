'''
Created on 2016年10月21日

@author: y35chen
'''
f = open('test.txt','a')
f.write('second line')
f.write('\nthird line')
f.flush()
f.close()
