#!/usr/bin/python
import socketserver
import socket
from threading import Thread
import time
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--src_port', help='', required=True)
parser.add_argument('--dst_port', help='', required=True)
parser.add_argument('--server', help='', required=True)
parser.add_argument('--raw', help='', action='store_true', required=False)
parser.add_argument('--strip', help='', action='store_true', required=False)
parser.add_argument('--hex', help='', action='store_true', required=False)
parser.add_argument('--auto', action='store', metavar='N', help='')
args = parser.parse_args()

class MyTCPConnection(Thread):
    def __init__(self, proxy_source):
        self.proxy_source = proxy_source
        self.proxy_target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def run(self):
        self.proxy_target.connect()

class MyTCPHandler(socketserver.BaseRequestHandler):
    BUFFER_SIZE = 4096

    def handle(self):
        try:
            while True:
                # msg = self.request.recv(self.BUFFER_SIZE)
        except IOError as e:
            print("Error occured {}".format(str(e)))

    # def forward_requests():

if __name__ == "__main__":
    print("Starting proxy server")
    server = socketserver.ThreadingTCPServer((args.server, args.src_port), MyTCPHandler)
    # thread = threading.Thread(target=server.serve_forever)
    thread = Thread(target=server.serve_forever).start()
    # thread.daemon = True
    # thread.start()

    print("Server taking requests on port " + args.src_port)
    print("Server forwarding requests to port " + args.src_port + " of " +
          args.server)

    while True:
        time.sleep(1)

    server.shutdown()
    server.server_forever()
