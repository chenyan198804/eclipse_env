'''
Created on 2016年7月19日

@author: y35chen
'''

def sort_priority(number, group):
    found = [False]
    def helper(x):
        if x in group:
            found[0] = True
            return (0,x)
        return (1,x)
    number.sort(key=helper)
    return found[0]

sort_priority(1, 562789108921)
