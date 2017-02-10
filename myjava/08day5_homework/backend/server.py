#!/usr/bin/env python
#_*_coding:utf-8_*_

import socketserver
import json
import datetime
from model.models import UserInfo,ChatRecord

class MyServer(socketserver.BaseRequestHandler):
    
    def handle(self):
        userinfo = UserInfo()
        chatrecord = ChatRecord()

        conn = self.request
        
        container = {'key':'','data':'','user':'','pwd':''}
        container['data']='ok...'        
        result = json.dumps(container)
        conn.sendall(result.encode('utf-8'))
        
        flag = True
    
        while flag:  
            data = conn.recv(1024)             
            rev_data = json.loads(data.decode('utf-8'))            
            print(rev_data['data'])
            
            if rev_data['data']=='exit':
                print('Goodbye')
                rev_result = json.dumps(rev_data)
                conn.send(rev_result.encode('utf-8'))
                flag = False
            #如果是空的，表示没有登录或者登录失败
            if not rev_data['key']:
                user = rev_data['user']
                pwd = rev_data['pwd']
                userid = userinfo.CheckLogin(user,pwd)
                
                if userid:
                    rev_data['key'] = userid
                    rev_data['data'] = 'welcome to login!'
                else:
                    rev_data['data'] = 'Login failed,Please input correct username and password! '
                
                rev_result = json.dumps(rev_data) 
                                    
                conn.sendall(rev_result.encode('utf-8'))    
            else:
                date = datetime.datetime.now()
                userid = rev_data['key']           
                message = rev_data['data']                
                chatrecord.InsertRecord(message, date, userid)
                
                rev_data['data']='Got it'
                rev_result = json.dumps(rev_data) 
                conn.send(rev_result.encode('utf-8'))  
        conn.close()
    
    
    def setup(self):
        pass

    def finish(self):
        pass
      
  
if __name__ == '__main__':
    server = socketserver.ThreadingTCPServer(('127.0.0.1',8081),MyServer) 
    server.serve_forever() 
