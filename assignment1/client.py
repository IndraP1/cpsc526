#!/usr/bin/python

import socket
# import sys

HOST, PORT = "localhost", 9999
# data = " ".join(sys.argv[1:])

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
while True:
    data = input("Enter: ")
    sock.sendall(bytes(data + "\n", "utf-8"))
    received = str(sock.recv(1024), "utf-8")
    sock.close()

    print("Sent:     {}".format(data))
    print("Received: {}".format(received))
