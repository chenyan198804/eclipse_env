'''
Created on 2016年7月14日

@author: y35chen
'''
#!/usr/bin/python
#Filename:using_file.py 


peom = '''\
programming is fun
when the work is done
if you wannna make your work also fun
    use Python!
'''

f = open('peom.txt','w')
f.write(peom)
f.close()

f = open('peom.txt') 

#if no mode is specified 'r'ead mode is assumed by default
while True:
    line = f.readline()
    if len(line) == 0:
        break
    print(line)
    
f.close()


