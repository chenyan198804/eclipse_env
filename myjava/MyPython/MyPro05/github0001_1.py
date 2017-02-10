'''
Created on 2016年10月10日

@author: y35chen
'''
import random

def genCode(length):
    s = "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()?"
    return "".join(random.sample(s,length))
#l=input("Enter the length of the random code: ")
#print(genCode(int(10)))

NUM_OF_TICKET = 10
result = set()
while len(result) < NUM_OF_TICKET:
    result.add(genCode(int(10)))

print(result)