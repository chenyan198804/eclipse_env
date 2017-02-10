'''
Created on 2016年10月12日

@author: y35chen
'''
import re

def statistics(file_path):
    f = open(file_path, 'r').read()
    f = re.findall(r'[\w\-\_\.\']+', f)
    print(len(f))
    return 0

if __name__ == '__main__':
    file_path = 'test.txt'
    statistics(file_path)