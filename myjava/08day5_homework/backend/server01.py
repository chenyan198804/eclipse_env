#!/usr/bin/env python
#_*_coding:utf-8_*_

import socketserver
import json
import time
from model.models import UserInfo,ChatRecord

class MyServer(socketserver.BaseRequestHandler):
    def setup(self):
        pass
    
    def handle(self):
        userinfo = UserInfo() #实例化一个用户表操作类
        chatrecord = ChatRecord()#实例化用户记录表操作类
        
        container = {'key':'','data':''}
        container['data']='ok...'
        
        conn = self.request
        
        result = json.dumps(container)
        conn.sendall(result.encode('utf-8'))
        
        Flag = True
        while Flag:
            try:
                data = conn.recv(1024)
                print(data)
                rev_data = json.loads(data.decode('utf-8'))
                if rev_data['data']=='exit':
                    conn.close()
                    break
                #如果key 为空，则表示用户没有登录或登录失败
                if not rev_data['key']:
                    name,pwd = rev_data['data']
                    re = 1
                    if re:
                        rev_data['key'] = re 
                        rev_data['data']= 'hi'
                    else:
                        rev_data['data']='failed'
                        rev_result = json.dumps(rev_data)
                    conn.sendall(rev_result.encode('utf-8'))
                #用户已登录   
                else:
                    datetime = time.strftime('%Y-%m-%d %H:%M:%S %Z',time.localtime(time.time()))
                    
                    if rev_data['data']=='list':
                        rev_data['data'] = ChatRecord.GetRecord(rev_data['key'])
                        pass
                    elif rev_data['data'].contains('yes'):
                        #如果用户输入yes，就把用户输入记录保存到数据
                        ChatRecord.InsertRecord(rev_data['data'], datetime,rev_data['key'])
                        rev_data['data']='I am gay'
                        #把聊天记录回复也保存到 数据库
                        ChatRecord.InsertRecord(rev_data['data'], datetime,rev_data['key'])
                    else:
                        #如果用户输入不是yes,把用户输入的记录保存到数据库
                        ChatRecord.InsertRecord(rev_data['data'], datetime,rev_data['key'])
                        rev_data['data']='what?'
                        #把聊天机器人回复也保存到数据库
                        ChatRecord.InsertRecord(rev_data['data'], datetime,rev_data['key'])
                        rev_result_1 = json.dumps(rev_data)
                    conn.sendall(rev_result_1.encode('utf-8')) 
                    
            except Exception as e:
                print(e)
                Flag = False

        def finish(self):
            pass
        
        
if __name__ == '__main__':
    server = socketserver.ThreadingTCPServer(('127.0.0.1',9988),MyServer)
    server.serve_forever()                          
                    
                                        
                        
                    