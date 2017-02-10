'''
Created on 2016年11月16日

@author: y35chen
'''
'''
import json
#import pickle
name_dic = {'name':'candy','age':'28'}
serializes_obj = json.dumps(name_dic)
print(serializes_obj)
print(json.loads(serializes_obj))

print(pickle.dumps(name_dic))

data = {'k1':123,'k2':'hello'}

p_str = pickle.dumps(data)
print(p_str)
print(type(p_str))

with open('D:/result.pk','w') as fp:
    pickle.dump(data,fp)

j_str = json.dumps(data)
print(j_str)
print(type(j_str))

with open('D:/myjava/08day3/Mybank/lock.json','w') as fp:
    json.dump(data,fp)
    
'''
import json
    
#name_dic = {'000001': {'name':'candy','age':28}}

'''
with open('D:/myjava/08day3/Mybank/lock.json','r') as fp:
    serializes_obj=json.dumps(fp.read())
    print(type(serializes_obj))
    print(serializes_obj)
    deserialization_obj = json.loads(serializes_obj)
    print(type(deserialization_obj))
    for key in deserialization_obj.keys():
        print(key)
        '''
#for key in deserialization_obj.keys():
#if key==self.username:
#                    sys.exit('User %s is locked!' %key)
#                else:
#                    print('correct account')
    
#file = 'D:/myjava/08day3/Mybank/account_lock.json'
#with open(file) as json_file:
#    data  = json.load(json_file)
    #print(data)
#dic = json.loads(fp)
#fp.close()
#print(dic)
#print(type(dic))
'''
name_dic = {'000001': {'name':'candy','age':28}}
print(type(name_dic))
serializes_obj = json.dumps(name_dic,sort_keys=True,indent =4,separators=(',', ': '),ensure_ascii=True )
print(type(serializes_obj))
print(serializes_obj)
    
print('*******************************')
deserialization_obj = json.loads(serializes_obj)
print(type(deserialization_obj))
print(deserialization_obj)
    
for key in deserialization_obj.keys():
    print(key)
print('*******************************')
'''
import sys   
def fun(account_numerber):
    with open('D:/myjava/08day3/Mybank/account.json','r') as fp:
        for line in fp:
            result = json.loads(line)
            print(result)
            print(type(result))
            print(result[account_numerber]['locked'])
            print(type(result[account_numerber]['locked']))
            if result[account_numerber]['locked']=='false':
                print('locked')
            else:
                print('unlocked')
                '''
            serializes_obj = json.dumps(result,sort_keys=True,indent = 4,separators=(',', ': '),ensure_ascii=True)
            print(type(serializes_obj))
            print(serializes_obj)
            deserialization_obj = json.loads(serializes_obj,encoding='utf-8')
            print(type(deserialization_obj))
            print(deserialization_obj)   
            
            for key in result:
                if key==account_number:
                    sys.exit('User %s is locked!' %key)
                else:
                    print('user unlocked')
                    sys.exit()
                 '''   

fun('000001')
                