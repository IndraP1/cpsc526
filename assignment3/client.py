#!/usr/bin/python
import argparse
import socket
import sys
import os
# import cryptography
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend

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
            iv = os.urandom(16)

            # secret = self.create_secret()
            self.initialize_connection(iv)
            msg = self.receive()
            # print("here!")
            if(msg == 'OK'):
                print("its good")

            self.generate_request()
            while True:
                print("here!")
                msg = self.receive()
                if len(msg) == 0:
                    print("stop!")
                    self.stop()
                elif msg == 'OK':
                    print("ok")
                    self.stop()
                else:
                    # decrypt message
                    print(msg)
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

        self.send(command)

    # def encrypt(iv, msg, key):
    #     encryptor = Cipher(
    #         algorithms.AES(key),
    #         modes.GCM(iv),
    #         backend=default_backend()
    #     ).encryptor()

        # ciphertext = encryptor.update(msg) + encryptor.finalize()

        # return ciphertext

    def send(self, msg):
        self.client_socket.sendall(bytes(msg + '\n', 'utf-8'))

    def receive(self):
        msg = self.client_socket.recv(self.BUFFER).decode('utf-8').rstrip('\n')
        return msg

    def stop(self):
        self.client_socket.close()
        exit()

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

    def initialize_connection(self, iv):
        print("iv: " + str(iv) + " cipher" + args.cipher)
        initialize = str(iv) + " " + args.cipher
        self.send(initialize)


def utf8len(s):
    return len(s.encode('utf-8'))

if __name__ == "__main__":
    print(args)
    connection = MyTCPConnection()
    connection.run()
