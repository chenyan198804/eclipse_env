#!/usr/bin/env python
#_*_coding:utf-8_*_
import socket
client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

ip_port = ('127.0.0.1',8892)
client.connect(ip_port)

while True:
    data = client.recv(1024)
    print(data)    
    inp = input('client:')
    client.send(inp.encode(encoding='utf_8'))

    if inp == 'exit':   
        break
