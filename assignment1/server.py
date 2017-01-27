#!/usr/bin/python

import socketserver

OK = 'OK'
PASSWORD_PROMPT = 'password for user: '
AUTHENTICATE_SUCCESS = 'login success'
AUTHENTICATE_FAIL = 'login fail'

class TCPHandler(socketserver.BaseRequestHandler):
    BUFFER_SIZE = 4096
    PASSWORD = 'test'

    def handle(self):
        while True:
            # authetnicate here
            self.authenticate()
            self.data = self.request.recv(self.BUFFER_SIZE)
            print("client {} wrote: ".format(self.client_address[0]))
            print(format(self.data))
            self.request.sendall(self.data)

    def receive(self):
        msg = self.request.recv(self.BUFFER_SIZE)
        return msg

    def send(self, msg):
        self.request.sendall(bytes(msg + '\n', 'utf-8'))
        # self.request.sendall(msg)

    def authenticate(self):
        self.send(PASSWORD_PROMPT)
        # passwd_attmpt =

if __name__ == "__main__":
    HOST, PORT = "localhost", 9999
    server = socketserver.TCPServer((HOST, PORT), TCPHandler)
    server.serve_forever()

