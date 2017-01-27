#!/usr/bin/python

import socketserver, subprocess

PASSWORD_PROMPT = 'Password for user: '
AUTHENTICATE_SUCCESS = 'Login success'
AUTHENTICATE_FAIL = 'Login fail'
INVALID_COMMAND = 'No command found: '
PROMPT_COMMAND = 'indra@localhost > '

class TCPHandler(socketserver.BaseRequestHandler):
    BUFFER_SIZE = 4096
    PASSWORD = 'test'

    def handle(self):
        # Authenticate the user
        self.authenticate()
        while True:
            self.send(PROMPT_COMMAND)
            command = self.receive()
            output = self.execute_command(command).decode('utf-8')
            if output == 'invalid':
                self.send_nl(INVALID_COMMAND + command)
            else:
                self.send_nl(output)

            print("client {} wrote: ".format(self.client_address[0]) + command)
            # self.request.sendall(self.data)

    def receive(self):
        msg = self.request.recv(1024).decode('utf-8').rstrip('\n')
        return msg

    def send(self, msg):
        self.request.sendall(bytes(msg, 'utf-8'))

    def send_nl(self, msg):
        self.request.sendall(bytes(msg + '\n', 'utf-8'))

    def authenticate(self):
        while True:
            self.send(PASSWORD_PROMPT)
            passwd_attmpt = self.receive()
            print("password attempt " + passwd_attmpt)
            if passwd_attmpt == self.PASSWORD:
                self.send_nl(AUTHENTICATE_SUCCESS)
                break
            else:
                self.send_nl(AUTHENTICATE_FAIL)

    def execute_command(self, command):
        if command == "ls":
            # subprocess.call(["ls", "-l"])
            output = subprocess.check_output(["ls", "-l"])
        else:
            output = "invalid"

        return output

if __name__ == "__main__":
    HOST, PORT = "localhost", 9999
    server = socketserver.TCPServer((HOST, PORT), TCPHandler)
    server.serve_forever()
