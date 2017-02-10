#!/usr/bin/env python
#_*_coding:utf-8_*_
import socket
client = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,0)
ip_port = ('127.0.0.1',9999)

while True:    
    inp = input('client:')

    if inp == 'exit':
        break
    client.sendto(inp.encode(encoding='utf_8'),ip_port)
    
client.close()
