#!/usr/bin/python
import argparse
import socketserver

OK = 'OK\n'

parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, help='', required=True)
parser.add_argument('--key', type=str, help='', required=False)
args = parser.parse_args()

class TCPHandler(socketserver.BaseRequestHandler):
    BUFFER_SIZE = 4096
    def handle(self):
        try:
            # Probably try to confirm secret yhere
            # self.authenticate if possible
            while True:
                command = self.receive()
                output = self.execute_command(command)
                if output == 'invalid':
                    self.send_n("error")
                else:
                    self.send_nl(OK)

        except IOError as e:
            print("Error occured {}".format(str(e)))

    def receive(self):
        msg = self.request.recv(1024).decode('utf-8').rstrip('\n')
        return msg

    def execute_command(self, command):
        print("test")

    def send_nl(self, msg):
        self.request.sendall(bytes(msg + '\n', 'utf-8'))

if __name__ == "__main__":
    print("Listening on port " + str(args.port))
    HOST = "localhost"
    server = socketserver.TCPServer((HOST, args.port), TCPHandler)
    # generate secret
    server.serve_forever()
