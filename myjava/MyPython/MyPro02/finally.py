'''
Created on 2016年7月15日

@author: y35chen
'''
#!/usr/bin/python 
#Filename: finally.py 

import time
try:
    f = open('poem.txt')
    while True:
        line = f.readline()
        if len(line) == 0:
            break
        print(len(line)) == 0;
        time.sleep(2)
except KeyboardInterrupt:
    print('!!You cancelled the reading from the file.')
finally:
    f.close()
    print('(Cleaning up: closed the file)')
    