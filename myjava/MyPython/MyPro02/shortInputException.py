'''
Created on 2016年7月15日

@author: y35chen
'''
class ShortInputException(Exception):
    '''A user-defined exception class'''
    def __init__(self,length,atleast):
        Exception.__init__(self)
        self.length = length
        self.atleast = atleast
try:
    text = input('Enter something--->')
    if len(text) < 3:
        raise ShortInputException(len(text),3)
    #other work can continues as usual here
except EOFError:
    print('Why did you do an EOF on me')
except ShortInputException as ex:
    print('Short InputException The input was {0} long, excepted\
    at least {1}'.format(ex.length, ex.atleast))
else:
    print('No exception was raise')   
        