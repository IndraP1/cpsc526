#!/usr/bin/python
import argparse
import socketserver
# import cryptography

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
            print("new client: " + self.client_address[0] + " crypto: NONE")
            iv, cipher = self.initialize_connection()
            # print("iv: " + iv + " cipher" + cipher)
            self.send(OK)

            while True:
                msg = self.receive()
                print("DEBUG:" + msg)
                command = str.split(msg)
                self.execute_command(command[0], command[1])
                break
            print(DONE)

        except IOError as e:
            print("Error occured {}".format(str(e)))

    def initialize_connection(self):
        initialize = self.receive()
        initialize_att = initialize.split(" ")

        iv = initialize_att[0]
        cipher = initialize_att[1]

        print("iv: " + iv + " cipher" + cipher)
        return iv, cipher

    def receive(self):
        msg = self.request.recv(self.BUFFER).decode('utf-8').rstrip('\n')
        return msg

    def execute_command(self, command, filename):
        if (command == "READ"):
            print("reading")
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

    def create_secret(self):
        secret = args.key
        i = 0
        if(args.cipher != "none"):
            if args.key is None:
                print("ERROR: Must specify key")
                exit()
            elif(args.cipher == "aes128"):
                while (utf8len(secret) < 16):
                    if(i == len(args.key)):
                        i = 0
                    secret = secret + args.key[i]
                    i += 1
            elif(args.cipher == "aes256"):
                while (utf8len(secret) < 32):
                    if(i == len(args.key)):
                        i = 0
                    secret = secret + args.key[i]
                    i += 1

        return secret


def utf8len(s):
    return len(s.encode('utf-8'))

if __name__ == "__main__":
    print("Listening on port " + str(args.port))
    HOST = "localhost"
    server = socketserver.TCPServer((HOST, args.port), TCPHandler)
    # generate secret
    server.serve_forever()
