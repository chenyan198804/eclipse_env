'''
Created on 2016年9月1日
调试不通过
@author: y35chen
'''

__author__='CQC'
# -*- coding:utf-8 -*-

import urllib.request
import re
from urllib.error import URLError

#糗事百科爬虫类

class QSBK:
    #初始化方法，定义变量
    def __init__(self):
        self.pageIndex = 1
        self.user_agent = 'Mozilla/4.0(compatible;MSIE 5.5;Windows NT)'
        #初始化headers
        self.headers = {'User-Agent':self.user_agent}
        #存放段子的变量，每个元素是每一页的段子们
        self.stories = []
        #存放程序是否继续运行变量
        self.enable = False
    #传入某一页的索引获得页面代码
    
    def getPage(self,pageIndex):
        proxy = urllib.request.ProxyHandler({'http':'http://10.144.1.10:8080'})
        opener = urllib.request.build_opener(proxy)
        urllib.request.install_opener(opener) 
        try:
            url = 'http://www.qiushibaike.com/hot/page/' + str(pageIndex)
            #构建request请求
            request = urllib.request.Request(url,headers = self.headers)
            response = urllib.request.urlopen(request,timeout=5)
            pageCode = response.read().decode('utf-8')      
            return pageCode
        except URLError as e:
            if hasattr(e, "reason"):
                print(u"链接糗事百科失败，错误原因",e.reason)
                return None
    #传入某一页的代码，返回本页不带图片的段子列表        
    def getPageItems(self,pageIndex):
        pageCode = self.getPage(pageIndex)
        if not pageCode:
            print('页面加载失败....')
            return None
        pattern=re.compile('<div class="author clearfix">.*?<h2>(.*?)</h2>.*?<div class="content">(.*?)</div>.*?<div class="stats".*?i class="number">(.*?)</i>(.*?)</span>.*?<span class="dash".*?i class="number">(.*?)</i>(.*?)</a>',re.S)
        items = re.findall(pattern, pageCode)
        #用来存储每页的段子
        pageStories = []
        #遍历正则表达式匹配信息
        for item in items:
            haveImg = re.search("img", item[3])
            if  not haveImg:
                replaceBR = re.compile('<br/>')  
                text = re.sub(replaceBR,"\n",item[1]) 
                #item[0]是段子手，item[1]是内容，item[2]是发布时间，item[4]是点赞数
                pageStories.append([item[0].strip(),text.strip(),item[2].strip(),item[4].strip()])
        return pageStories
            
    #加载并提取页面内容，加入列表中
    def loadPage(self):
        #如果当前未看页数少于两页，则加载新一页
        if self.enable == True:
            if len(self.stories) < 2:
                pageStories = self.getPage(self.pageIndex)
                if pageStories:
                    self.stories.append(pageStories) 
                    self.pageIndex += 1
                        
        #调用该方法，每次敲回车打印输出一个段子
    def getOneStory(self,pageStories):
        for story in pageStories:               
            input_result = input()
            self.loadPage()
            if input_result == "Q":
                self.enable = False
                return 
            #print(u"第%d页\t发布人：%s\t发布时间：%s\t赞：%s\n%s"% (self.pageIndex-1,story[0],story[2],story[3],story[1])) 
            header = "第%s页\t发布人:%s\t赞:%s\n"\
                     % (self.pageIndex - 1, story[0],story[2])
            body = story[1] + '\n=================================\n'
            print(header, body)
 
    def start(self):
        print(u"正在读取糗事百科，按回车查看新段子，Q退出")        
        #使变量为True，程序可以正常运行
        self.enable = True
        self.loadPage()
        #局部变量，控制当前读到第几页
        while self.enable:
            if len(self.stories)>0:
                pageStories = self.stories[0]
                del self.stories[0]
                self.getOneStory(pageStories)
                
spider = QSBK()
spider.start()         