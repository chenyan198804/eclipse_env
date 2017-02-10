'''
Created on 2016年10月19日

@author: y35chen
'''
#_*_coding:utf-8_*_
print_num = input('Which loop do you want it to be printed out!')

count = 0
while count < 10:
    if  count == int(print_num):
        print('There you got the number:', count)
        choice = input('Do you want to continue the loop?(y/n)')
        if choice == 'n':
            break
        else:
            while(int(print_num) <= int(count)):
                print_num = input('Which loop do you want it to be printed out!')
                print(u'已经过了')
    else:
        print('Loop:',count)
    count += 1

else:
    print('loop:',count)
