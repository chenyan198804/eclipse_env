'''
Created on 2016年7月8日

@author: y35chen
'''
bri = set(['brazil','russia','india'])
print('india' in bri)
print('usa' in bri)
bric = bri.copy()
bric.add('china')
print(bric)
print(bric.issuperset('bri'))
bri.remove('russia')
print(bri & bric)
