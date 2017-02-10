'''
Created on 2016年10月27日

@author: y35chen
'''

#!/bin/usr/env python
#_*_coding:utf-8_*_ 
import re, math 
def get_customer_salary():
    while True:
        salary  = input("Please enther monthhly salary：")
        if __is_valid_num(salary):return int(salary)
        print("[Warn] Please enter a valid number \n")
        
#检查输入的工资是不是数字
def __is_valid_num(salary):
    num_pattern = re.compile(r"\d*")
    if num_pattern.match(salary):return True
    return False

def get_customer_selection():
    while True:
        selection = input("Please enter the goods numbers you would like to buy:\n")
        if __is_valid_num(selection):
            if __is_a_valid_selection(int(selection)): return int(selection)
            print("[Warn]Please enter a valid selection number")
            continue
def __is_a_valid_selection(selection):
    try:
        if 1 <= selection <=  get_total_amount_of_products():return True
        return False
    except:
        print("Please enter a valid integer")
        
def get_products_list():
    return {'Flower':50,'AppleWatch':1000,'Kindle':900,'Car':20000,'Apartment':1500000}#是字典，所以要通过名字来获取价格

def get_total_amount_of_products():
    return len(get_products_list())

def mapping_type_code_for_product():
    return ["Flower","AppleWatch","Kindle","Car","Apartment"]  #返回的必须是列表，不然不能通过索引进去获取

def get_product_price(type_code):
    return get_products_list()[get_product_name(type_code)]

def get_product_name(type_code):
    return mapping_type_code_for_product()[type_code-1]

def get_lowest_price_of_product():
    price_list = []
    for k,v in  get_products_list().items():
        price_list.append(v)
    return min(price_list)

def get_highest_price_of_products():
    price_list = []
    for k,v in  get_products_list().items():
        price_list.append(v)
    return max(price_list)

def still_can_buy_something(left_money):
    if left_money < get_lowest_price_of_product():return False
    return True

def still_want_to_buy_something():
    while True:
        answer = input('Do you still want to buy something?(y/n)\n')
        result = is_a_valid_answer(answer)
        if result == 'yes':return True
        if result == 'no': return False
        print("[Warn]Please enter [yes/no] or [y/n]\n")
        
def is_a_valid_answer(answer):
    yes_pattern = re.compile(r"[Yy][Ee][Ss]|[Yy]")
    no_pattern = re.compile(r"[Nn][Oo]|[Nn]")
    if yes_pattern.match(answer):return "yes"
    if no_pattern.match(answer):return "no"
    return False

def show_shopping_list():     
    counter = 1
    for i in mapping_type_code_for_product():
        print('''
         (%d) %s:%s RMB '''%(counter,i+" "*(10-len(i)),str(get_products_list()[i])))        
        counter += 1
        print("\n")
        
def is_affordable(left_money,product_price):
    if left_money >= product_price: return True
    return False

def time_needed_to_work_for_buying_products(salary, price):
    result = float(price)/salary
    return get_formatting_time(int(math.ceil(result)))

def get_formatting_time(months):
    if months < 12:return("%d months" %months)
    years = months / 12
    months = months % 12
    return ("%d years,%d months"%(years,months))

#主程序从这里开始
if __name__ == '__main__':
    #获取月工资
    salary = get_customer_salary()
    total_money = salary
    #初始化购物车
    shopping_cart = []
    while True:
        #打印购物车列表
        show_shopping_list()
        #判断剩余资金是否能够购买列表中的最低价商品
        if still_can_buy_something(total_money):
            #获取用户需要购买的商品编号
            selection = get_customer_selection()
            #获取此商品的价格
            product_price = get_product_price(selection)
            #获取此商品的名称
            product_name = get_product_name(selection)
            #判断剩余资金是否购买此商品
            if total_money >= product_price:
                total_money -= product_price
                #打印购买成功信息
                print("Congratulations!You bought a %s successfully!\n" %product_name)
                #将商品加入购物车
                shopping_cart.append(product_name)
                #打印剩余资金
                print("You still have %d RMB left\n" %total_money)
                #判断是否还想购买其他商品
                if not still_want_to_buy_something():
                    print("Thank you for your coming")
                    break
            else:
                #输出还需要工作多久才能够买
                format_time = time_needed_to_work_for_buying_products(salary, product_price-total_money)
                print("Sorry, you can not afford this product! \n ")
                print("You have to work '%s' to get it!\n"%format_time)
                #判断是否还想购买其他商品
                if not still_want_to_buy_something():
                    break
        else:
            #输出提示你已经无法负担任何商品
            print("Sorry, you do not have enough money to purchase anything!\n")
            break
    #打印购物车列表    
    print("You bought %s" %shopping_cart)
    


        
            