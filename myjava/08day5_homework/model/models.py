#!/usr/bin/env python
#_*_coding:utf-8_*_

from uility.sqlhelper import MySqlHelper

class UserInfo(object):
    def __init__(self):
        self.sqlHelper = MySqlHelper()
    
    def CheckLogin(self,user,pwd):
        '''验证用户名是否合法
        @param name:用户名
        @param pwd:密码
        @return 如果登录成功，则返回用户的自增ID，否则
        '''
        sql = '''select Nid, Name,Password from userinfo where Name=%s and Password = %s'''
        params= user,pwd
        result = self.sqlHelper.GetSimple(sql, params)
        if not result:
            return False
        else:
            return result['Nid']

class ChatRecord(object):
    def __init__(self):
        self.sqlHelper = MySqlHelper()
        
    def InsertRecord(self,message,date,userid):
        '''插入聊天记录
        @param message：聊天信息
        @param data:时间
        @param  userid：用户id
        @return 如果聊天记录插入成功，返回True 否则
        
        '''
        sql = '''insert into chatrecord(Message,Date,UserId) values(%s,%s,%s) '''
        params = message,date,userid
        self.sqlHelper.InsSamples(sql, params)
        
    def GetRecord(self,userid):
        pass
    
'''    
import datetime
date =datetime.datetime.now()
c=ChatRecord()       
userid = 1  
message = 'hi'

c.InsertRecord(message, date, userid)

'''