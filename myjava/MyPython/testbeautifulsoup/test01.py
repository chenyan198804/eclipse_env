'''
Created on 2016年8月12日

@author: y35chen
'''
from bs4 import BeautifulSoup
htlm = """
<html><head><title>The Dormouse's story</title></head>
<body>
<p class="title" name="dromouse"><b>The Dormouse's story</b></p>
<p class="story">Once upon a time there were three little sisters; and their names were
<a href="http://example.com/elsie" class="sister" id="link1"><!-- Elsie --></a>,
<a href="http://example.com/lacie" class="sister" id="link2">Lacie</a> and
<a href="http://example.com/tillie" class="sister" id="link3">Tillie</a>;
and they lived at the bottom of a well.</p>
<p class="story">...</p>
"""
soup = BeautifulSoup(htlm)
    
print(soup.prettify())
print('##############')
print(soup.title)
print(soup.head)
print(soup.a)
print(soup.p)
print(type(soup.a))
print('##############')
print(soup.name)
print(soup.head.name)
print('##############')
print(soup.p.attrs)
print(soup.p['class'])
soup.p['class']="newClass"
print(soup.p)
print('##############')
print(soup.p.string)
print(type(soup.p.string))
print('##############')
print(type(soup.name))
print(soup.name)
print(soup.attrs)
print('##############')
print(soup.a)
print(soup.a.string)
print(type(soup.a.string))

if type(soup.a.string) == 'bs4.element.Comment':
    print(soup.a.string)