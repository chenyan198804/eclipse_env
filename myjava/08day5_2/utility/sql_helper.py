#!/usr/bin/env python
#_*_coding:utf-8_*_
import pymysql
from main import config

class MySqlHelper(object):
    def __init__(self):
        self.__ConnDict = config.ConnDict
    
    def GetDict(self,sql,params):
        conn=pymysql.connect(**self.__ConnDict) 
        cur = conn.cursor()
        
        cur.execute(sql,params)
        data = cur.fetchall()
        
        cur.close()
        conn.close()
        return data
    
    def GetOne(self,sql,params):
        conn=pymysql.connect(**self.__ConnDict) 
        cur = conn.cursor()
        cur.execute(sql,params)
        data = cur.fetchone()
        cur.close()
        conn.close()
        return data
'''
sql = 'select * from admin where username=%s and password=%s'
params = ('Lucy','123')
f = MySqlHelper()
result = f.GetOne(sql, params)
print(result)
'''