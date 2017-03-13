#!/usr/bin/python
import argparse
import math
import os
import time
import socketserver
import random
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.backends import default_backend

OK = 'OK'
NEXT = 'NEXT'
FILE = 'FILE'
DONE = 'done\n'

parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, help='', required=True)
parser.add_argument('--key', type=str, help='', required=False)
args = parser.parse_args()


class TCPHandler(socketserver.BaseRequestHandler):
    BUFFER = 4096

    def handle(self):
        try:
            iv_b, cipher = self.initialize_connection()
            print(gettime() + " new client: " + 
                    self.client_address[0] + " crypto: " + cipher)
            if (cipher != "none"):
                justify, secret_b = self.create_secret(cipher)
                initial_response = self.encrypt(justify, iv_b, secret_b, OK)
                self.send_b(initial_response)

                command_b = self.receive_b()
                decryptcommand_b = self.decrypt(iv_b, secret_b, command_b)
                command_s = str.split(decryptcommand_b.decode("utf-8").strip())
                print(gettime() + " command: " + str(decryptcommand_b.decode("utf-8").strip()))
                self.execute_command(command_s[0], command_s[1], justify, iv_b, secret_b)
                print(gettime() + " " + DONE)
            elif (cipher == "none"):
                print("here now")
                self.send(OK)
                msg = self.receive_s()
                command = str.split(msg)
                print(gettime() + " command: " + msg)
                self.execute_command_none(command[0], command[1])
                print(gettime() + " " + DONE)

        except Exception as e:
            print("Error: Could not decrypt")
            print("Error occured {}".format(str(e)))

    def decrypt(self, iv_b, secret_b, msg_b):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(secret_b), modes.CBC(iv_b), backend=backend)

        decryptor = cipher.decryptor()
        return decryptor.update(msg_b) + decryptor.finalize()

    def encrypt(self, justify, iv_b, secret_b, plaintext):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(secret_b), modes.CBC(iv_b), backend=backend)

        encryptor = cipher.encryptor()
        length = utf8len(plaintext)
        if (length/16 <= 1):
            plaintext_pad = plaintext.ljust(justify-1)
        else:
            factor = math.ceil(length/16)
            plaintext_pad = plaintext.ljust((factor * justify)-1)
        
        encoded = bytes(plaintext_pad + '\n', 'utf-8')

        return encryptor.update(encoded) + encryptor.finalize()

    def initialize_connection(self):
        iv_b = self.receive_b()
        self.send(OK)
        cipher = self.receive_s()

        return iv_b, cipher

    def receive_b(self):
        msg = self.request.recv(self.BUFFER)
        return msg

    def receive_s(self):
        msg = self.request.recv(self.BUFFER).decode('utf-8').rstrip('\n')
        return msg

    def execute_command_none(self, command, filename):
        if (command == "READ"):
            try:
                with open(filename) as f:
                    for line in f:
                        self.send_nl(line)

                        msg = self.receive_s()
                        if (msg != "NEXT"):
                            break
                self.send(OK)
                f.close()
            except Exception as e:
                self.send(FILE)
                print(gettime() + " Error: Could not open file " + filename) 

    def execute_command(self, command, filename, justify, iv_b, secret_b):
        if (command == "READ"):
            try:
                with open(filename) as f:
                    for line in f:
                        line_b = self.encrypt(justify, iv_b, secret_b, line)
                        self.send_b(line_b)

                        msg_b = self.receive_b()
                        dmsg_b = self.decrypt(iv_b, secret_b, msg_b)
                        dmsg_s = dmsg_b.decode("utf-8").strip()
                        if (dmsg_s != "NEXT"):
                            break
                final_response = self.encrypt(justify, iv_b, secret_b, OK)
                self.send_b(final_response)
                f.close()
            except Exception as e:
                no_file = self.encrypt(justify, iv_b, secret_b, FILE)
                self.send_b(no_file)
                print(gettime() + " Error: Could not open file " + filename) 

        if (command == "WRITE"):
            ok_write = self.encrypt(justify, iv_b, secret_b, OK)
            self.send_b(ok_write)
            f = open(filename, 'w')
            while True:
                msg_b = self.receive_b()
                dmsg_b = self.decrypt(iv_b, secret_b, msg_b)
                dmsg_s = dmsg_b.decode("utf-8").strip()
                if (dmsg_s == 'OK'):
                    break
                f.write(dmsg_s+"\n")  
                next_line = self.encrypt(justify, iv_b, secret_b, NEXT)
                self.send_b(next_line)
            f.close()

            final_response = self.encrypt(justify, iv_b, secret_b, OK)
            self.send_b(final_response)

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
            justify = 16
            while (utf8len(secret) < 16):
                if(i == len(args.key)):
                    i = 0
                secret = secret + args.key[i]
                i += 1
        elif(cipher == "aes256"):
            justify = 32
            while (utf8len(secret) < 32):
                if(i == len(args.key)):
                    i = 0
                secret = secret + args.key[i]
                i += 1
        else:
            secret = ""

        secret_b = bytes(secret, 'utf-8')

        return justify, secret_b


def utf8len(s):
    return len(s.encode('utf-8'))

def gettime():
    return time.strftime("%H:%M:%S") 

if __name__ == "__main__":
    print("Listening on port " + str(args.port))
    if(args.key == None):
        args.key = ''.join(random.choice('0123456789ABCDEF') for i in range(32))
    print("Using secret key " + str(args.key))
    HOST = "localhost"

    server = socketserver.TCPServer((HOST, args.port), TCPHandler)
    # generate secret
    server.serve_forever()
