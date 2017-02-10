'''
Created on 2016年10月13日

@author: y35chen
'''

from PIL import Image

def change_resolution(picPath, reslution):
    img = Image.open(picPath)
    x, y = img.size
    print("x,y",x, y)
    changex = float(x) / reslution[0]
    changey = float(y) / reslution[1]

    if changex > 1 or changey > 1:
        change = changex if changex > changey else changey
        print("change",change)
        print("reslution",int(reslution[0] / change), int(reslution[1] / change))
        img.resize((int(x / change), int(y / change))).save('result.jpg')
    
if __name__ == '__main__':
    change_resolution('chenyan.jpg', (1136, 640))