#!/usr/bin/python

import socket
# import sys

HOST, PORT = "localhost", 9999
# data = " ".join(sys.argv[1:])

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
while True:
    data = input("Enter: ")
    sock.send(bytes(data + "\n", "utf-8"))
    # print("Sent:     {}".format(data))

    received = sock.recv(1024).decode('utf-8')
    print("{}".format(received))
sock.close()
