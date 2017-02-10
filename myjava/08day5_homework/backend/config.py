#!/usr/bin/env python
#_*_coding:utf-8_*_

from pymysql import cursors
ConnDict = dict(host='localhost',user='root',passwd='',db='milktea',charset='utf8',cursorclass=cursors.DictCursor)
