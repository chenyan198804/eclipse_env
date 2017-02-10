'''
Created on 2016年10月31日

@author: y35chen
'''
import re
def get_customer_salary():
    salary = input('Please input your salary')
    if __is_valid_num(salary):
        return int(salary)
    else:
        print('[Warn]Please input an valid ')
    
def __is_valid_num(salary):
    num_pattern = re.compile(r'\d*')    
    if num_pattern.match(salary):return True
    return False

def get_product_list():
    return {'Flower':50,'AppleWatch':1000,'Car':50000,'Apartment':5000000}

def mapping_product_code():
    return ['Flower','AppleWatch','Car','Apartment']

def show_shopping_list():
    counter = 1
    for i in mapping_product_code():
        print('(%d) %s:%s RMB \n'%(counter,i+" "*(10-len(i)),str(get_product_list()[i])))
        counter += 1

def still_can_buy_something(left_money):
    if left_money < get_lowest_price_of_product():return False
    return True

def get_lowest_price_of_product():
    price_list = []
    for i in get_product_list():
        price_list.append(get_product_list()[i])
    return min(price_list)
            
def get_customer_selection():
    while True:
        selection = input('Please input your selection')
        if __is_valid_num(selection):
            if __is_valid_selection(int(selection)):
                return int(selection)
            print('Please input a valid selection')
            continue
    
def __is_valid_selection(selection):
    try:
        if 1 <= selection <= len(get_product_list()):return True
        return False
    except:
        print('Please input a valid integer')
        
def get_product_name(type_code):
    return mapping_product_code()[type_code-1]

def get_product_price(type_code):
    return get_product_list()[get_product_name(type_code)]

def want_to_buy_something():    
    yes_pattern = re.compile(r'[Yy][Ee][Ss]|[Yy]')
    no_pattern = re.compile(r'[Nn][Oo]|[Nn]')
    while True:
        answer = input('Do you still want to buy something?(y/n)')
        if yes_pattern.match(answer):return True
        if no_pattern.match(answer):return False
    print('[Warn]Please input yes/no or y/n ')
                
if __name__ == '__main__':
    #获取员工工资
    salary = get_customer_salary()
    #购物总资金等于工资
    total_money = salary
    #初始化购物车列表
    shopping_cart = [] 
    list = []
    while True:
    #展示能购买的列表
        list = show_shopping_list()
        if still_can_buy_something(total_money): 
        #请求用户输入商品编号       
            selection = get_customer_selection()
        #购物名称
            product_name = get_product_name(selection)
        #购物价格
            product_price = get_product_price(selection)
            if total_money >= product_price:
                total_money  -= product_price
                shopping_cart.append(product_name)
                print('Congraduation!You have bought %s for %d RMB, and you still have %d RMB left!'%(product_name,product_price,total_money))
                if not want_to_buy_something():break
            else:
                print('You can\'t afford this product, please choose a cheaper one')
                if not want_to_buy_something():break
        else:
            print('Sorry, you don\'t have enought money to buy anything')
              
    print("You bought %s" %shopping_cart)
           
    