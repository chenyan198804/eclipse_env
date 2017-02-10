'''
Created on 2016年11月11日

@author: y35chen
'''
def AlexReadlines():
    seek = 0
    while True:
        with open('D:/temp.txt','r') as f:
            f.seek(seek)
            data = f.readline()
            if data:
                seek = f.tell()
                yield data
            else:
                return
print(AlexReadlines())
for item in AlexReadlines():
    print(item)