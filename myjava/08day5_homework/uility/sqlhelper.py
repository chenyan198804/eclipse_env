#!/usr/bin/env python
#_*_coding:utf-8_*_
import pymysql
from backend import config

class MySqlHelper(object):
    def __init__(self):
        self.__ConnDict = config.ConnDict
    
    def GetSimple(self,sql,params):
        '''获取单条数据
        @param sql:sql语句
        @param params：参数
        @return：数据
        '''
        conn = pymysql.connect(**self.__ConnDict )
        cur = conn.cursor()
        
        cur.execute(sql,params)
        data = cur.fetchone()
        
        cur.close()
        conn.close()
        return data
    
    def GetDict(self,sql,params):
        '''获取多条数据（字典类型）

        '''
        conn = pymysql.connect(**self.__ConnDict )
        cur = conn.cursor()
        
        cur.execute(sql,params)
        data = cur.fetchall()
        
        cur.close()
        conn.close()
        return data
    
    def InsSamples(self,sql,params):
        '''插入单条数据
        @return : 受影响的数据
        '''
        conn = pymysql.connect(**self.__ConnDict)
        cur = conn.cursor()
        
        count = cur.execute(sql,params)
        conn.commit()
        
        cur.close()
        conn.close()
        return count
    
    def InsSample_ReturnId(self,sql,params):
        '''插入单条数据，
        @return : 返回自增id
        '''
        conn = pymysql.connect(**self.__ConnDict)
        cur = conn.cursor()
        
        cur.execute(sql,params)
        idnumber = cur.lastrowid
        conn.commit()
        
        cur.close()
        conn.close()
        return idnumber
                
        