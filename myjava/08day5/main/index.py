#!/usr/bin/env python
#_*_coding:utf-8_*_
import pymysql
'''
#######################select#######################
try:
    conn=pymysql.connect(host='localhost',user='root',passwd='',db='08day5',charset='utf8')   
    cur = conn.cursor()
    
    reCount = cur.execute('select * from userinfo')
    data = cur.fetchall()

    cur.close()
    conn.close()
    
    print(reCount)
    print(data)

except Exception:
    print('error')
    

#######################insert#######################
try:
    conn=pymysql.connect(host='localhost',user='root',passwd='',db='08day5',charset='utf8')   
    cur = conn.cursor()
    
    sql = "insert into userinfo (id,name) values(%s,%s)"
    params = ('4','Candy')
    
    reCount = cur.execute(sql,params)
    conn.commit()

    cur.close()
    conn.close()
    
    print(reCount)

except Exception:
    print('error')

####################### delete#######################

try:
    conn=pymysql.connect(host='localhost',user='root',passwd='',db='08day5',charset='utf8')   
    cur = conn.cursor()

    sql = 'delete from userinfo where id =%s'
    params = 3

    reCount = cur.execute(sql,params)
    conn.commit()


    cur.close()
    conn.close()
    
    print(reCount)

except Exception:
    print('error')
    
    ####################### update#######################

try:
    conn=pymysql.connect(host='localhost',user='root',passwd='',db='08day5',charset='utf8')   
    cur = conn.cursor()

    sql = 'update userinfo set name = %s where id =7'
    params = 'LUCY'

    reCount = cur.execute(sql,params)
    conn.commit()

    cur.close()
    conn.close()
    
    print(reCount)

except Exception:
    print('error')
      
    
    ####################### insert list#######################
try:
    conn=pymysql.connect(host='localhost',user='root',passwd='',db='08day5',charset='utf8')   
    cur = conn.cursor()
    
    li = [
          ('1','alex'),
          ('3','Fish')
          ]

    reCount = cur.executemany('insert into userinfo (id,name) values(%s,%s)',li)
    conn.commit()

    cur.close()
    conn.close()
    
    print(reCount)

except Exception:
    print('error')
    
   
try:
    conn=pymysql.connect(host='localhost',user='root',passwd='',db='08day5',charset='utf8')   
    cur = conn.cursor()
    
    
    sql = 'update userinfo set name = %s where id =7'  
    params = ('500',)  
    reCount = cur.executemany(sql,params)
    
    sql = 'update userinfo1 set name = %s where id =1'  
    params = ('700',)  
    reCount = cur.executemany(sql,params)
    conn.commit()

    cur.close()
    conn.close()
    
    print(reCount)

except Exception:
    print('error')
     
         
from pymysql import cursors

conn=pymysql.connect(host='localhost',user='root',passwd='',db='08day5',charset='utf8',cursorclass=cursors.DictCursor)   

cur = conn.cursor()
    
reCount = cur.execute('select * from userinfo')
#data = cur.fetchall()
data = cur.fetchone()
print(data)


data = cur.fetchone()
print(data)

#cur.scroll(0,mode='absolute')
cur.scroll(-1,mode='relative')
data = cur.fetchone()
print(data)

#cur.scroll(-1,mode='relative')
#cur.scroll(0,mode='absolute')

cur.close()
conn.close()

print(reCount)



from pymysql import cursors
conn=pymysql.connect(host='localhost',user='root',passwd='',db='08day5',charset='utf8',cursorclass=cursors.DictCursor)   

cur = conn.cursor()
    
sql = 'insert into media(address) values(%s)'  
params = ('/usr/bin/a.txt',) 

reCount = cur.execute(sql,params)
conn.commit()

new_id = cur.lastrowid
print(new_id)

cur.close()
conn.close()
    '''
def func(a,b,*c):
    print(type(a),a)
    print(type(b),b)
    print(type(c),str(c))
    
f= func(1,2,3,4)
print(f)



