#!/usr/bin/env python
#_*_coding:utf-8_*_
from Mybank.CreditCard import CreditCard
from Mybank.AccountCheck import AccountCheck
from Mybank.BankRe import BankRe
import json
import time
import sys
import os

class CreditCardService(CreditCard):
    def __init__(self,account_number):
        CreditCard.__init__(self,account_number)
        
        
    def Withdraw(self):
        crash = input('Please enter the withdraw crash amount:')
        with open('D:/myjava/08day3/Mybank/account.json','r') as fp:            
            for line in fp:
                result = json.loads(line)
                old_banlance = result[self.account_number]['banlance']
                banlance = float(old_banlance)-float(crash)*1.05
                if float(old_banlance) < float(crash):
                    print('Only %s Banlance left,please take another actions.'%(old_banlance))
                    break
                else:    
                    result[self.account_number]['banlance']=json.dumps(banlance)
                    with open('D:/myjava/08day3/Mybank/account.json','w') as fp:
                        json.dump(result,fp)
                        record="WithDraw %s at %s"%(crash,time.strftime('%Y-%m-%d %H:%M:%S %Z',time.localtime(time.time())))
                        print(record)
                        self.bills(record)
           
           
    def checkaccount(self):
        with open('D:/myjava/08day3/Mybank/account.json','r') as fp:            
            for line in fp:
                result = json.loads(line)
                banlance = result[self.account_number]['banlance']
                print("The account %s banlance is %s"%(self.account_number,banlance))
        record="Check account at %s"%(time.strftime('%Y-%m-%d %H:%M:%S %Z',time.localtime(time.time())))
        self.bills(record)

    
    def repay(self):
        crash = input('Please enter the repay crash amount:')
        with open('D:/myjava/08day3/Mybank/account.json','r') as fp:
            
            for line in fp:
                result = json.loads(line)
                old_banlance = result[self.account_number]['banlance']
                banlance = int(old_banlance)+int(crash)
                result[self.account_number]['banlance']=json.dumps(banlance)
                print(result[self.account_number]['banlance'])
                
                with open('D:/myjava/08day3/Mybank/account.json','w') as fp:
                    json.dump(result,fp)
        record="Repay %s at %s"%(crash,time.strftime('%Y-%m-%d %H:%M:%S %Z',time.localtime(time.time())))
        print(record)
        self.bills(record)
    
    def transfer(self):
        target_account = input('Please input your target card to transfer:')
        account = AccountCheck(self.account_number)
        account.TargetAccountVerify(target_account)
        
        crash = input('Please enter the transfer crash amount:')
        with open('D:/myjava/08day3/Mybank/account.json','r') as fp:
            
            for line in fp:
                result = json.loads(line)
                old_banlance = result[self.account_number]['banlance']
                target_old_banlance = result[target_account]['banlance']
                if float(old_banlance) < float(crash):
                    print('Only %s Banlance left,please take another actions.'%(old_banlance))
                    break
                else:
                    banlance = float(old_banlance)-float(crash)

                    target_banlance = int(target_old_banlance) + int(crash)
                    print("The balance of %s is %s"%(self.account_number,banlance) )
                
                    result[self.account_number]['banlance']=json.dumps(banlance)
                    result[target_account]['banlance']=json.dumps(target_banlance)
                
                    with open('D:/myjava/08day3/Mybank/account.json','w') as fp:
                        json.dump(result,fp)                    
                        record="Transfer from %s to %s  %s RMB at %s"%(self.account_number,target_account,crash,time.strftime('%Y-%m-%d %H:%M:%S %Z',time.localtime(time.time())))
                        print(record)
                        self.bills(record)
        
    def bills(self,record):

        path = os.path.exists('D:/myjava/08day3/Mybank/%s_bills.json'%(self.account_number))  
        if path==False:
            f = open('D:/myjava/08day3/Mybank/{0}_bills.json'.format(self.account_number),'w') 
            f.close() 

        with open('D:/myjava/08day3/Mybank/%s_bills.json'%(self.account_number),'r') as fp:
            for line in fp:
                present_bills = json.loads(line)
                present_bills.append(record)
            with open('D:/myjava/08day3/Mybank/%s_bills.json'%(self.account_number),'w') as fp:
                json.dump(present_bills,fp)


    def serviceSelection(self,serviceId):
        if serviceId=='1':
            self.Withdraw()
            self.moreServiceAction()
        if serviceId=='2':
            self.checkaccount()
            self.moreServiceAction()
        if serviceId=='3':
            self.repay()
            self.moreServiceAction()
        if serviceId=='4':
            self.transfer()
            self.moreServiceAction()
        if serviceId=='5':
            sys.exit("Thank you for using my bank,,please take your card back!")
            
            
    def moreServiceAction(self):
        answer = input('Do you want more actions?yes or no?')
        bankRe = BankRe()
        action = bankRe.yesNoPattern(answer)
        while action:
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
            serviceId = input(' ')
            self.serviceSelection(serviceId)
        else:
            sys.exit("Thank you for using my bank,please take your card back!")    