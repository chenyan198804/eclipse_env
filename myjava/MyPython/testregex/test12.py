'''
Created on 2016年9月5日

@author: y35chen
'''
import re

s = """
hhsdj dskj hello src=scvt yes jdjsds
src=234 yes
hello src=python yes ksa
"""

r1 = r"hello src=(.+) yes"
print(re.findall(r1, s))