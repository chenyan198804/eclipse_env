#!/usr/bin/env python
#_*_coding:utf-8_*_
'''
def outer(fun):
    def wrapper(arg):
        print('hello')
        result = fun(arg)
        return result
        print('there')
    return wrapper
@outer
def Func1(arg):
    print('func1',arg)
    return 'return'
response = Func1('alex')
print(response)



def log(func):
    def wrapper(*args,**kw):
        print('call %s():' %func.__name__)
        return func(*args,**kw)
    return wrapper

@log
def data():
    print('2013-12-25')
    
data()


def log(text):
    def decorator(func):
        def wrapper(*args,**kw):
            print('%s %s():' %(text,func.__name__))
            return func(*args,**kw)
        return wrapper
    return decorator

@log('execute')
def data():
    print('2013-12-25')
    
data()

print(data.__name__)




def Filter(before_func,after_func):
    def outer(main_func):
        def wrapper(request,kargs):
            before_result = before_func(request,kargs)
            if(before_func != None):
                return before_result;
            
            main_result = main_func(request,kargs)
            if(main_result != None):
                return main_result;
            
            after_result = after_func(request,kargs)
            if(after_result != None):
                return after_result;
            
            return wrapper
        return outer
    
    
    @Filter(AccountFilter.Before,AccountFilter.After)
    def List(request,kargs):
        pass
                        
'''
