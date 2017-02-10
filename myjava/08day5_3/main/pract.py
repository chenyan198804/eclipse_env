#!/usr/bin/env python
#_*_coding:utf-8_*_
from socket import *
from time import ctime
from threading import Thread

class ClientHandler(Thread):
    """Handles a client request."""
    def __init__(self, client):
        Thread.__init__(self)
        self._client = client

    def run(self):
        self._client.send(bytes(ctime() + '\nHave a nice day!' , 'ascii'))
        self._client.close()

HOST = "localhost"
PORT = 15200 # Port number was changed here
BUFSIZE = 1024
ADDRESS = (HOST, PORT)

server = socket(AF_INET, SOCK_STREAM)
server.bind(ADDRESS)
server.listen(5)

# The server now just waits for connections from clients
# and hands sockets off to client handlers
while True:
    print('Waiting for connection')
    client, address = server.accept()
    print('...connected from:', address)
    handler = ClientHandler(client)
    handler.start()