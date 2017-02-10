#!/usr/bin/env python
#_*_coding:utf-8_*_
import socketserver
import os

class MyServer(socketserver.BaseRequestHandler):
    def handle(self):
        base_path = 'D:/temp' 
        conn = self.request
        print('connected...')
        while True:
            pre_data = conn.recv(1024) 
            print(pre_data)
            cmd,file_name,file_size = pre_data.split('|')
            recv_size = 0
            file_dir = os.path.join(base_path,file_name)
            f = open(file_dir,'wb')
            Flag = True
            while Flag:
                if int(file_size) > recv_size:
                    data = conn.recv(1024)
                    recv_size += len(data)
                    f.write(data)
                else:
                    recv_size = 0
                    Flag = False

            print('upload successed!')
            f.close() 
            
instance = socketserver.ThreadingTCPServer(('127.0.0.1',9999),MyServer)
instance.serve_forever()                      