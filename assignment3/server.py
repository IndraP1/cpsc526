#!/usr/bin/python
import argparse
import socketserver

OK = 'OK'
DONE = 'done\n'

parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, help='', required=True)
parser.add_argument('--key', type=str, help='', required=False)
args = parser.parse_args()


class TCPHandler(socketserver.BaseRequestHandler):
    BUFFER = 4096

    def handle(self):
        try:
            # Probably try to confirm secret here
            # self.authenticate if possible
            print("new client: " + self.client_address[0] + " crypto: NONE")
            while True:
                msg = self.receive()
                print("DEBUG:" + msg)
                command = str.split(msg)
                self.execute_command(command[0], command[1])
                # command = self.receive()
                # output = self.execute_command(command)
                break
            print(DONE)

        except IOError as e:
            print("Error occured {}".format(str(e)))

    def receive(self):
        msg = self.request.recv(self.BUFFER).decode('utf-8').rstrip('\n')
        return msg

    def execute_command(self, command, filename):
        if (command == "READ"):
            try:
                with open(filename) as f:
                    for line in f:
                        self.send(line)
                self.send(OK)
            except Exception as e:
                self.send_nl("ERROR: File " + filename + " does not exist")
                print("Error occured {}".format(str(e)))

        elif (command == "WRITE"):
            # TODO
            print("WIP Write")

    def send_nl(self, msg):
        self.request.sendall(bytes(msg + '\n', 'utf-8'))

    def send(self, msg):
        self.request.sendall(bytes(msg, 'utf-8'))

if __name__ == "__main__":
    print("Listening on port " + str(args.port))
    HOST = "localhost"
    server = socketserver.TCPServer((HOST, args.port), TCPHandler)
    # generate secret
    server.serve_forever()
