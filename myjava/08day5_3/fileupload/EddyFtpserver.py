#!/usr/bin/env python
#_*_coding:utf-8_*_

import socketserver
import time
import os
current_dir = os.getcwd()
class EddyFtpserver(socketserver.BaseRequestHandler):
    def recvfile(self,filename):
        print('starting reve file!')
        f = open(filename,'wb')
        self.request.send('ready')
        while True:
            data = self.request.recv(4096)
            if data == 'EOF':
                print('recv file success!')
                break
            f.write(data)
        f.close()
        
    def sendfile(self,filename):
        print('starting send file')
        self.request.send('ready')
        time.sleep(1)
        f = open(filename,'rb')
        while True:
            data = f.read(4096)
            if not data:
                break
            self.request.sendall(data)
        f.close()
        time.sleep(1)
        self.request.send('EOF')
        print('send file success!')
        
    def handle(self):
        print('get connection from:'),self.client_address
        while True:
            try:
                data = self.request.recv(4096)
                print('get data',data)
                if not data:
                    print('break the connection!')
                    break
                else:
                    action,filename = data.split()
                    
                if action == 'put':
                    filename = current_dir+'/'+os.path.split(filename)[1]
                    self.recvfile(filename)
                    
                elif action == 'get':
                    self.sendfile(filename)
                    
                else:
                    print('get error!')
                    continue
            except Exception as e:
                    print('get error at',e)
        
if __name__=='__main__':
    host = '127.0.0.1'
    port = 8080
    s =socketserver.ThreadingTCPServer((host,port),EddyFtpserver)
    s.serve_forever()                
                    