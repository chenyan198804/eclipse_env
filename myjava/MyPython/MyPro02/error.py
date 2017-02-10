'''
Created on 2016年7月15日

@author: y35chen
'''
def get_error_details():
    return(2, 'second error details')
errnum,errstr = get_error_details()
print(errnum)
print(errstr)

a, *b =[1,2,3,4]
print(a)
print(b)


    