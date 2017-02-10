'''
Created on 2016年10月31日

@author: y35chen
'''
import re 

def get_product_list():
    return {'Flower':50,'AppleWatch':1000,'Car':50000,'Apartment':5000000}

def get_customer_selection():
    while True:
        selection = int(input('please input your selection'))
        print(type(selection))
        if __is_valid_num(selection):
            if __is_valid_selection(selection):
                return selection
            print('Please input a valid selection')
            continue
        
def __is_valid_selection(selection):
    if 1 <= selection <= len(get_product_list()): return True
    return False


def __is_valid_num(salary):
    num_pattern = re.compile(r'\d*')    
    if num_pattern.match(salary):return True
    return False

l = len(get_product_list())
print(l)
print(type(l))

