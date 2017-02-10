#!/usr/bin/env python
#_*_coding:utf-8_*_
import socket
sk = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

ip_port = ('127.0.0.1',10110)
sk.bind(ip_port)
sk.listen(5)

while True:
    print('Waiting for connection')
    conn,address = sk.accept()
    conn.send("hello".encode(encoding='utf_8'))
    flag = True
    
    while flag:  
        data = conn.recv(1024) 
        print(data)
        #print(type(data))
        #print(type('exit'))
        if data == 'exit'.encode(encoding='utf_8'):
            flag = False
        print(flag)
        conn.send("Sb".encode(encoding='utf_8'))        
    conn.close()
