'''
Created on 2016年8月9日

@author: y35chen
'''
def __hash__(self):
    if self.denominator == 1:
        #Get integers right.
        return hash(self.numerator)
    #Expensive check, but definitely correct.
    if self == float(self):
        return hash(float(self))
    else:
        #Use tuple's hash to avoid a high collision rate on
        #simple fractions
        return hash((self.numerator,self.denomiator))