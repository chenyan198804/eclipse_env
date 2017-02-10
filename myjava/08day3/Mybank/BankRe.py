#!/usr/bin/env python
#_*_coding:utf-8_*_
import re
class BankRe(object):
    def __init__(self):
        pass
    def yesNoPattern(self,answer):
        yes_pattern = re.compile(r"[Yy][Ee][Ss]|[Yy]")
        no_pattern = re.compile(r"[Nn][Oo]|[Nn]")
        if yes_pattern.match(answer):return True
        if no_pattern.match(answer):return False
        return False
    

