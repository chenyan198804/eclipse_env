'''
Created on 2016年10月9日

@author: y35chen
'''
#!/usr/bin/env python
#-*- coding:utf-8 -*-

__author__ = 'chenyan'
from PIL import  Image,ImageDraw,ImageFont
import random
msgNum = str(random.randint(1,99))
print(msgNum)
# Read image
im = Image.open('D:/myjava/MyPython/MyPro05/chenyan.png')
w,h = im.size
wDraw = 0.8 * w
hDraw = 0.08 * w

# Draw image
font = ImageFont.truetype('C:/Windows/Fonts/Arial.ttf', 30) 
# use absolute font path to fix 'IOError: cannot open resource'
draw = ImageDraw.Draw(im)
draw.text((wDraw,hDraw), msgNum, font=font, fill=(255,31,255))

# Save image
im.save('chenyan_msg.png', 'png')

