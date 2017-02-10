'''
Created on 2016年10月13日

@author: y35chen
'''
#!/usr/local/bin/python
#coding=utf-8

import re

def count_the_words(path):
    with open(path) as f:
        text = f.read()
        words_list = re.findall(r'[a-zA-Z0-9\']+', text)
        print(words_list)
        count = len(words_list)
    return count

if __name__ == '__main__':
    nums = count_the_words('test.txt')
    print(nums)