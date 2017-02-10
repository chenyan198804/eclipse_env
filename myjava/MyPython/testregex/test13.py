'''
Created on 2016年9月5日
爬取图片
@author: y35chen
'''
#！/usr/bin/python
import re 
import urllib.request

def getHtml(url):
    proxy = urllib.request.ProxyHandler({'http':'http://10.144.1.10:8080'})
    opener = urllib.request.build_opener(proxy)
    urllib.request.install_opener(opener)
    user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
    headers = {'User-Agent': user_agent}
    try:
        request = urllib.request.Request(url,headers=headers)
        html = urllib.request.urlopen(request)
        page = html.read().decode('utf-8')
        return page
    except:
        return None
def getImg(page):
    reg = r'src="(.*?\.jpg)"'
    imgre = re.compile(reg)
    imglist = re.findall(imgre,page)
    x = 0
    for imgurl in imglist:
        urllib.request.urlretrieve(imgurl,'%s.jpg' %x)
        x += 1

page = getHtml('http://www.qiushibaike.com/hot')
print(page)
getImg(page)
