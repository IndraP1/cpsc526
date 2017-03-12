#!/usr/bin/python
import argparse
import os
import socketserver
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.backends import default_backend

OK = 'OK'
DONE = 'done\n'

parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, help='', required=True)
parser.add_argument('--key', type=str, help='', required=True)
args = parser.parse_args()


class TCPHandler(socketserver.BaseRequestHandler):
    BUFFER = 4096

    def handle(self):
        try:
            print("new client: " + self.client_address[0] + " crypto: NONE")
            iv_b, cipher = self.initialize_connection()
            secret_b = self.create_secret(cipher)
            initial_response = self.encrypt(iv_b, secret_b, OK)
            print("encrypted: " + str(initial_response))
            self.send_b(initial_response)

            # while True:
            #     msg = self.receive()
            #     print("DEBUG:" + msg)
            #     command = str.split(msg)
            #     self.execute_command(command[0], command[1])
            #     break
            print(DONE)

        except IOError as e:
            print("Error occured {}".format(str(e)))

    def encrypt(self, iv_b, secret_b, plaintext):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(secret_b), modes.CBC(iv_b), backend=backend)

        encryptor = cipher.encryptor()

        ct = encryptor.update(b"a secret message") + encryptor.finalize()

        return (ct)

    def initialize_connection(self):
        iv_b = self.receive_b()

        print("iv: " + str(iv_b))
        self.send(OK)

        cipher = self.receive_s()
        print("cipher: " + cipher)

        return iv_b, cipher

    def receive_b(self):
        msg = self.request.recv(self.BUFFER)
        return msg

    def receive_s(self):
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

    def send_b(self, msg):
        self.request.sendall(msg)

    def create_secret(self, cipher):
        secret = args.key
        i = 0

        if(cipher == "aes128"):
            while (utf8len(secret) < 16):
                if(i == len(args.key)):
                    i = 0
                secret = secret + args.key[i]
                i += 1
        elif(cipher == "aes256"):
            while (utf8len(secret) < 32):
                if(i == len(args.key)):
                    i = 0
                secret = secret + args.key[i]
                i += 1

        secret_b = bytes(secret, 'utf-8')
        print("secret_b:" + str(secret_b))

        return secret_b


def utf8len(s):
    return len(s.encode('utf-8'))

if __name__ == "__main__":
    print("Listening on port " + str(args.port))
    HOST = "localhost"

    server = socketserver.TCPServer((HOST, args.port), TCPHandler)
    # generate secret
    server.serve_forever()
