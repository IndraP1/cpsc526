#!/usr/bin/python
import argparse
import socket
import sys
import os
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.backends import default_backend

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
            self.initialize_connection(iv_b)
            msg_b = self.receive_b()
            print("encrypted: " + str(msg_b))

            dmsg_b = self.decrypt(iv_b, secret_b, msg_b)
            print("decrypted: " + dmsg_b.decode("utf-8").strip())

            # Connection established between client and server
            if(dmsg_b.decode("utf-8").strip() == 'OK'):
                command_s = self.generate_request()
                print(command_s)
                command_b = self.encrypt(justify, iv_b, secret_b, command_s)
                self.send_b(command_b)

                # while True:
                #     print("here!")
                #     msg = self.receive()
                #     if len(msg) == 0:
                #         print("stop!")
                #         self.stop()
                #     elif msg == 'OK':
                #         print("ok")
                #         self.stop()
                #     else:
                #         # decrypt message
                #         print(msg)
        except Exception as e:
            print("Error occured {}".format(str(e)))

    def generate_request(self):
        if (args.command == "write"):
            print("payload")
            # TODO send small amounts of data at a time
            payload = sys.stdin.read()
            print(payload)
            command = "WRITE " + args.filename
        elif (args.command == "read"):
            command = "READ " + args.filename
        else:
            print("ERROR: Invalid command")
            exit()

        return command

    def encrypt(self, justify, iv_b, secret_b, plaintext):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(secret_b), modes.CBC(iv_b), backend=backend)

        encryptor = cipher.encryptor()
        print("len: " + str(utf8len(plaintext)))
        length = utf8len(plaintext)
        # TODO fix factor
        print(length/16)
        if (length/16 <= 1):
            plaintext_pad = plaintext.ljust(justify-1)
        else:
            factor = math.ceil(length/16)
            plaintext_pad = plaintext.ljust((factor * justify)-1)
        
        encoded = bytes(plaintext_pad + '\n', 'utf-8')

        print("encoded" + str(len(encoded)))
        return encryptor.update(encoded) + encryptor.finalize()

    def decrypt(self, iv_b, secret_b, msg_b):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(secret_b), modes.CBC(iv_b), backend=backend)

        decryptor = cipher.decryptor()
        return decryptor.update(msg_b) + decryptor.finalize()

    def initialize_connection(self, iv):
        print("iv: " + str(iv) + " cipher" + args.cipher)
        # initialize = str(iv) + " " + args.cipher
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

        secret_b = bytes(secret, 'utf-8')

        return justify, secret_b


def utf8len(s):
    return len(s.encode('utf-8'))

if __name__ == "__main__":
    print(args)
    connection = MyTCPConnection()
    connection.run()
