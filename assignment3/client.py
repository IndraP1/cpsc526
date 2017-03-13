#!/usr/bin/python
import argparse
import fileinput
import socket
import math
import sys
import os
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.backends import default_backend

OK = 'OK'
NEXT = 'NEXT'

parser = argparse.ArgumentParser()
parser.add_argument('--command', type=str, help='', required=True)
parser.add_argument('--filename', type=str, help='', required=True)
parser.add_argument('--hostname', type=str, help='', required=True)
parser.add_argument('--port', type=int, help='', required=True)
parser.add_argument('--cipher', type=str, help='', required=True)
parser.add_argument('--key', type=str, help='', required=False)
args = parser.parse_args()


class MyTCPConnection():
    BUFFER = 4096

    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((args.hostname, args.port))

    def run(self):
        try:
            iv_b = os.urandom(16)

            justify, secret_b = self.create_secret(args.cipher)

            # Initializing connection
            if (args.cipher != "none"):
                self.initialize_connection(iv_b)
                msg_b = self.receive_b()
                dmsg_b = self.decrypt(iv_b, secret_b, msg_b)
                # Connection established between client and server
                if(dmsg_b.decode("utf-8").strip() == 'OK'):
                    command_s = self.generate_request()
                    command_b = self.encrypt(justify, iv_b, secret_b, command_s)
                    self.send_b(command_b)

                    if (args.command == "write"):
                        self.start_write(justify, iv_b, secret_b)

                        msg_b = self.receive_b()
                        dmsg_b = self.decrypt(iv_b, secret_b, msg_b)
                        dmsg_s = dmsg_b.decode("utf-8").strip()
                        if dmsg_s == 'OK':
                            print("ok")
                            self.stop()

                    elif (args.command == "read"):
                        print("FILE CONTENTS: ")
                        print("===================")
                        while True:
                            msg_b = self.receive_b()
                            dmsg_b = self.decrypt(iv_b, secret_b, msg_b)
                            dmsg_s = dmsg_b.decode("utf-8").strip()
                            
                            if dmsg_s == 'OK':
                                print("===================")
                                print("ok")
                                self.stop()
                            if dmsg_s == 'FILE':
                                print("Error: File " + args.filename + "does not exist")
                                self.stop()
                            print(dmsg_s)
                            next_line = self.encrypt(justify, iv_b, secret_b, NEXT)
                            self.send_b(next_line)

            elif (args.cipher == "none"):
                self.initialize_connection(iv_b)
                msg = self.receive_s()
                # Connection established between client and server
                if(msg == 'OK'):
                    cmd = self.generate_request()
                    self.send_s(cmd)

                    if (args.command == "read"):
                        print("FILE CONTENTS: ")
                        print("===================")
                        while True:
                            msg = self.receive_s()
                            
                            if msg == 'OK':
                                print("===================")
                                print("ok")
                                self.stop()
                            if msg == 'FILE':
                                print("Error: File " + args.filename + "does not exist")
                                self.stop()
                            print(msg)
                            self.send_s(NEXT)

        except Exception as e:
            print("Error: Wrong key")
            print("Error occured {}".format(str(e)))
            self.stop()

    def start_write(self, justify, iv_b, secret_b):
        msg_b = self.receive_b()
        dmsg_b = self.decrypt(iv_b, secret_b, msg_b)
        dmsg_s = dmsg_b.decode("utf-8").strip()
        if (dmsg_s == "OK"):
            try:
                for line in sys.stdin:
                    new_line = line.strip()
                    line_b = self.encrypt(justify, iv_b, secret_b, new_line)
                    self.send_b(line_b)

                    msg_b = self.receive_b()
                    dmsg_b = self.decrypt(iv_b, secret_b, msg_b)
                    dmsg_s = dmsg_b.decode("utf-8").strip()
                    if (dmsg_s != "NEXT"):
                        break
                final_response = self.encrypt(justify, iv_b, secret_b, OK)
                self.send_b(final_response)
            except Exception as e:
                print("Error occured {}".format(str(e)))

    def generate_request(self):
        if (args.command == "write"):
            command = "WRITE " + args.filename

        elif (args.command == "read"):
            command = "READ " + args.filename
        else:
            print("ERROR: Invalid command")
            exit()

        return command

    def encrypt(self, justify, iv_b, secret_b, plaintext):
        backend = default_backend()

        if (args.cipher != "none"):
            cipher = Cipher(algorithms.AES(secret_b), modes.CBC(iv_b), backend=backend)

            encryptor = cipher.encryptor()
            length = utf8len(plaintext)
            if (length/16 <= 1):
                plaintext_pad = plaintext.ljust(justify-1)
            else:
                factor = math.ceil(length/16)
                plaintext_pad = plaintext.ljust((factor * justify)-1)
        else:
            print("here")
            cipher = Cipher(algorithms.AES(), modes.CBC(), backend=backend)

        encryptor = cipher.encryptor()
        encoded = bytes(plaintext_pad + '\n', 'utf-8')

        return encryptor.update(encoded) + encryptor.finalize()

    def decrypt(self, iv_b, secret_b, msg_b):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(secret_b), modes.CBC(iv_b), backend=backend)

        decryptor = cipher.decryptor()
        return decryptor.update(msg_b) + decryptor.finalize()

    def initialize_connection(self, iv):
        self.send_b(iv)
        msg = self.receive_s()
        if msg == 'OK':
            self.send_s(args.cipher)

    def send_b(self, msg):
        self.client_socket.sendall(msg)

    def send_s(self, msg):
        self.client_socket.sendall(bytes(msg, 'utf-8'))

    def receive_b(self):
        msg = self.client_socket.recv(self.BUFFER)
        return msg

    def receive_s(self):
        msg = self.client_socket.recv(self.BUFFER).decode('utf-8').rstrip('\n')
        return msg

    def stop(self):
        self.client_socket.close()
        exit()

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
            justify = 0

        secret_b = bytes(secret, 'utf-8')

        return justify, secret_b


def utf8len(s):
    return len(s.encode('utf-8'))

if __name__ == "__main__":
    connection = MyTCPConnection()
    connection.run()
