#!/usr/bin/env python
#_*_coding:utf-8_*_
import socketserver
class MyServer(socketserver.BaseRequestHandler):
    
    def handle(self):
        print(self.request)
        print(self.client_address)
        print(self.server)
        conn = self.request
        conn.send("hello".encode(encoding='utf_8'))
        flag = True
    
        while flag:  
            data = conn.recv(1024) 
            print(data)
        
            if data == 'exit'.encode(encoding='utf_8'):
                flag = False
            conn.send("Sb".encode(encoding='utf_8'))        
        conn.close()
    
    
    def setup(self):
        pass

    def finish(self):
        pass
      
  
if __name__ == '__main__':
    server = socketserver.ThreadingTCPServer(('127.0.0.1',8892),MyServer) 
    server.serve_forever() 