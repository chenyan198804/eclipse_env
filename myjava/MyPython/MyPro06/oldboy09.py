'''
Created on 2016年10月24日

@author: y35chen
'''
from filecmp import cmp
msg = "what's your company's name"

msg_list = msg.split("'")
print('|'.join(msg_list))
print('______'.join(msg_list))

msg += ' sliver king'  #需要多次开辟内存空间
print(msg)

msg_chinese ="燕子"
msg_english = 'Yanzi'
print(len(msg_english))
print(len(msg_chinese))

x='Abd'
y='Abl'
print(x.startswith('A'))
#print(ord(x))
#print(ord(y))
print(help(cmp))
