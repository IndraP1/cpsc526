#!/usr/bin/python
import socketserver
import socket
from threading import Thread
import time
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--src_port', type=int, help='', required=True)
parser.add_argument('--server', type=str, help='', required=True)
parser.add_argument('--dst_port', type=int,  help='', required=True)
parser.add_argument('--raw', help='', action='store_true', required=False)
parser.add_argument('--strip', help='', action='store_true', required=False)
parser.add_argument('--hex', help='', action='store_true', required=False)
parser.add_argument('--auto', action='store', metavar='N', help='')
args = parser.parse_args()

class MyLogger():
    mode = 'auto'

    def __init__(self):
        if(args.raw):
            self.mode == 'raw'
        elif(args.strip):
            self.mode == 'strip'
        elif(args.raw):
            self.mode == 'hex'
        else:
            self.mode == 'auto'

    def log(self, msg):
        split = msg.decode('utf-8').splitlines()

        if(self.mode == 'auto'):
            print ('<--- ', end='')
            print ('\n<--- '.join(split))

logger = MyLogger()

class MyTCPConnection(Thread):
    BUFFER_SIZE = 4096

    def __init__(self, proxy_source):
        Thread.__init__(self)
        self.proxy_source = proxy_source
        self.proxy_target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.proxy_target.connect((args.server, args.dst_port))

    def run(self):
        print ("Connection being forwarded")
        try:
            while True:
                msg = self.receive()
                if len(msg) == 0:
                    break
                self.proxy_source.send_source(msg)
        except Exception as e:
            print("Error occured {}".format(str(e)))

        self.stop()

    def send_dest(self, msg):
        logger.log(msg)
        # split = msg.decode('utf-8').splitlines()
        # print ('---> ', end='')
        # print ('\n---> '.join(split))
        self.proxy_target.send(msg)

    def receive(self):
        msg = self.proxy_target.recv(self.BUFFER_SIZE)
        return msg

    def stop(self):
        self.proxy_target.close()

class MyTCPHandler(socketserver.BaseRequestHandler):
    BUFFER_SIZE = 4096

    def handle(self):
        connection = MyTCPConnection(self)
        connection.start()

        try:
            while True:
                msg = self.receive()
                if len(msg) == 0:
                    break
                # print ("Received from source: " + msg.decode('utf-8'))
                # split = msg.decode('utf-8').splitlines()
                # print("<--- split: " + split)
                connection.send_dest(msg)
        except Exception as e:
            print("Error occured {}".format(str(e)))

        connection.stop()

    def send_source(self, msg):
        # split = msg.decode('utf-8').splitlines()
        # print ('<--- ', end='')
        # print ('\n<--- '.join(split))
        logger.log(msg)
        self.request.send(msg)

    def receive(self):
        msg = self.request.recv(self.BUFFER_SIZE)
        return msg

    def stop(self):
        print("Closing connection")
        self.request.close()

if __name__ == "__main__":
    print("Starting proxy server")
    server = socketserver.ThreadingTCPServer(('localhost', args.src_port), MyTCPHandler)
    thread = Thread(target=server.serve_forever).start()

    print("Server taking requests on port " + str(args.src_port))
    print("Server forwarding requests to port " + str(args.src_port) + " of " +
          args.server)

    while True:
        time.sleep(1)

    server.shutdown()
    server.server_forever()
