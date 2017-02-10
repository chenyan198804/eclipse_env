#!/usr/bin/env python
#_*_coding:utf-8_*_
from utility.sql_helper import MySqlHelper

class Admin(object):
    def __init__(self):
        self.__helper = MySqlHelper()

    def GetOne(self,idr):
        sql = 'select * from admin where id=%s'
        params = (idr,)
        return self.__helper.GetOne(sql, params)
    
    def CheckValidate(self,username,password):
        sql = 'select * from admin where username=%s and password=%s'
        params = username,password
        result = self.__helper.GetDict(sql, params)
        return result