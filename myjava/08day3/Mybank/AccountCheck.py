
'''
Created on 2016,12,13

@author: y35chen

################################################################
#############    1.Input username and password    ##############
####    2.Print welcome information after login success    #####
####    3.Print error information after login failed    ########
################################################################
'''
#!/usr/bin/env python
#_*_coding:utf-8_*_

import json
class AccountCheck(object):
    def __init__(self,account_number):
        self.account_number=account_number
     
     
    def AccountVerify(self):
        with open('D:/myjava/08day3/Mybank/account.json','r') as fp:
            Flag = True
            while Flag:
                for line in fp:
                    result = json.loads(line)
                    for key in result:
                        if key==self.account_number:
                            print('Welcome to Login your bank account!')
                            Flag = False
                            return True
                if Flag:
                        self.account_number=input('Please enter correct account:')
                        return False
    
    def LockVerify(self):
        with open('D:/myjava/08day3/Mybank/account.json','r') as fp:
            for line in fp:
                result = json.loads(line)
                if result[self.account_number]['locked']=='true':
                    print('Your account is locked!')
                    return False
                else:                    
                    return True
    
    def PasswordCheck(self):
        
        retry_limit = 3
        retry_count = 0
        match_flag = False
        
        while retry_count < retry_limit: 
            password = input('Please input your password:')
            with open('D:/myjava/08day3/Mybank/account.json','r') as fp:
                for line in fp:   
                    result = json.loads(line)
                    if result[self.account_number]['password']==password:
                        print(
'''
#################################################
#####    Please Selecte your service type:  #####
#####         1.Withdraw                   ######
#####         2.Check account               #####
#####         3.Repay                       #####
#####         4.Transfer                   ######
#####         5.Exit                       ######
#################################################
    ''')
                        match_flag = True
                        break
                if match_flag == False:
                    retry_count += 1
                    chance = 3 - retry_count
                    print('Please input your correct password!You have only %s retry chance now,and the account will be locked after 3times error try!'%chance)
                else:
                        break
                    
        else:
            with open('D:/myjava/08day3/Mybank/account.json','r') as fp:
                for line in fp:   
                    result = json.loads(line)
                    result[self.account_number]['locked']=json.dumps(True)
                    
                    with open('D:/myjava/08day3/Mybank/account.json','w') as fp:
                        json.dump(result,fp)
                    print('Your account is locked')


    def TargetAccountVerify(self,target_account):
        with open('D:/myjava/08day3/Mybank/account.json','r') as fp:
            for line in fp:
                result = json.loads(line)
                Flag = True
                while Flag:
                    for key in result:
                        #print(key)                    
                        #print(target_account)
                        if key==target_account:                        
                            print('Are you sure to transfer money to target_account:',target_account)
                            Flag = False
                            break
                            
                    if Flag:
                        target_account=input('Please enter correct account:')

                        
    

