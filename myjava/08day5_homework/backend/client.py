#!/usr/bin/env python
#_*_coding:utf-8_*_
import socket
import json

def main():   
    client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    ip_port = ('127.0.0.1',8081)
    client.connect(ip_port)
    
    while True:
        data = client.recv(1024)           
        rev_data = json.loads(data.decode('utf-8'))
        print(rev_data['data'])
        
        if rev_data['data']=='exit':
            print('Goodbye')
            break
                
        if not rev_data['key']:
            
            user = input('username:')
            pwd = input('password:')
            rev_data['user']= user
            rev_data['pwd']= pwd
            
            result = json.dumps(rev_data)
            
            client.sendall(result.encode('utf-8'))
            
        else:
            inp = input('client:')
            rev_data['data']=inp
            
            result = json.dumps(rev_data)
            client.send(result.encode(encoding='utf_8'))
    
if __name__ == '__main__':
    main()