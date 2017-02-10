'''
Created on 2016年8月26日

@author: y35chen
'''
import re
#将正则表达式编译成Pattern对象
pattern = re.compile(r'world')
#使用search（）查找匹配的子串，不存在能匹配的子串将返回None
#这个例子中使用match（）无法匹配成功
match = re.search(pattern, 'hello world!')
if match:
    #使用match获得分组信息
    print(match.group())