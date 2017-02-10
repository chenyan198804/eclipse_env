#!/usr/bin/env python
#_*_coding:utf-8_*_
import json
with open('D:/myjava/08day3/Mybank/account.json','r') as fp:
    for line in fp:
        print(line)
        print(type(line))
        result = json.loads(line)
        print(result)