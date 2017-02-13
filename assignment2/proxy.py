#!/usr/bin/python
import socketserver
import socket
from threading import Thread
import time
import select
import argparse
import datetime

parser = argparse.ArgumentParser()
parser.add_argument('--src_port', type=int, help='', required=True)
parser.add_argument('--server', type=str, help='', required=True)
parser.add_argument('--dst_port', type=int,  help='', required=True)
parser.add_argument('--raw', help='', action='store_true', required=False)
parser.add_argument('--strip', help='', action='store_true', required=False)
parser.add_argument('--hex', help='', action='store_true', required=False)
parser.add_argument('--auto', action='store', type=int, metavar='N', help='')
args = parser.parse_args()

class MyLogger():

    def __init__(self):
        self.mode = ''

    def log(self, msg, dir):
        if(args.strip):
            newmsg = bytearray(msg)
            for i in range(len(newmsg)):
                if ((newmsg[i] < 32 or newmsg[i] > 127) and newmsg[i] != 10):
                    newmsg[i] = 46

            split = newmsg.decode('ascii').splitlines()
            if(dir == 'in') :
                print ('<--- ', end='')
                print ('\n<--- '.join(split))
            if(dir == 'out') :
                print ('---> ', end='')
                print ('\n---> '.join(split))

        elif(args.hex):
            for i in range(0, len(msg), 16):
                line = msg[i:i+16]
                if (len(line) > 8):
                    first = line[:8]
                    second = line[8:]
                else:
                    first = line
                    second = []
                first = ''.join('%02x'%i for i in first)
                second = ''.join('%02x'%i for i in second)

                newmsg = bytearray()
                for j in line:
                    if ((j < 32 or j > 127) and j != 10):
                        newmsg.append(46)
                    else:
                        newmsg.append(j)

                newsg = newmsg.decode('ascii')

                if (dir == 'out'):
                    print ('---> ', end='')
                    print('{:08x} '.format(i), end='')
                    print('{:24s}'.format(first), end='')
                    print('{:24s}'.format(second), end='')
                    print('|{:s}|'.format(newsg))

                if (dir == 'in'):
                    print ('<--- ', end='')
                    print('{:08x} '.format(i), end='')
                    print('{:24s}'.format(first), end='')
                    print('{:24s}'.format(second), end='')
                    print('|{:s}|'.format(newsg))

        elif(args.auto):
            for i in range(0, len(msg), args.auto):
                line = msg[i:i+args.auto]
                newline = []
                for j in line:
                    if ((j < 32 or j > 127) and j != 10 and j != 9 and j != 13):
                        newline.append('\\' + format(j, '02x'))
                    else:
                        newline.append(chr(j))
                newline = ''.join(newline)
                if (dir == 'out'):
                    print ('---> ', end='')
                    print('{:s}'.format(newline))
                elif (dir == 'in'):
                    print ('<--- ', end='')
                    print('{:s}'.format(newline))

        else:
            split = msg.decode('unicode_escape').splitlines()
            if(dir == 'in') :
                print ('<--- ', end='')
                print ('\n<--- '.join(split))
            if(dir == 'out') :
                print ('---> ', end='')
                print ('\n---> '.join(split))

logger = MyLogger()

class MyTCPConnection(Thread):
    BUFFER_SIZE = 4096

    def __init__(self, proxy_source):
        Thread.__init__(self)
        self.proxy_source = proxy_source
        self.proxy_target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.proxy_target.connect((args.server, args.dst_port))

    def run(self):
        try:
            while True:
                readable, _, _ = select.select([self.proxy_target], [], [], 0)

                if self.proxy_target in readable:
                    msg = self.receive()
                    if len(msg) == 0:
                        break
                    self.proxy_source.send_source(msg)
        except Exception as e:
            print("Error occured {}".format(str(e)))

        self.stop()

    def send_dest(self, msg):
        logger.log(msg, 'out')
        self.proxy_target.send(msg)

    def receive(self):
        msg = self.proxy_target.recv(self.BUFFER_SIZE)
        return msg

    def stop(self):
        self.proxy_target.close()

class MyTCPHandler(socketserver.BaseRequestHandler):
    BUFFER_SIZE = 4096

    def handle(self):
        now = datetime.datetime.now()
        print("New connection: " + now.strftime("%Y-%m-%d %H:%M") +
              " from localhost")

        connection = MyTCPConnection(self)
        connection.start()

        try:
            while True:
                readable, _, _ = select.select([self.request], [], [], 0)

                if self.request in readable:
                    msg = self.receive()
                    if len(msg) == 0:
                        break
                    connection.send_dest(msg)
        except Exception as e:
            print("Error occured {}".format(str(e)))

        connection.stop()

    def send_source(self, msg):
        logger.log(msg, 'in')
        self.request.send(msg)

    def receive(self):
        msg = self.request.recv(self.BUFFER_SIZE)
        return msg

    def stop(self):
        print("Connection closed.")
        self.request.close()

if __name__ == "__main__":
    server = socketserver.ThreadingTCPServer(('localhost', args.src_port), MyTCPHandler)
    thread = Thread(target=server.serve_forever).start()

    print("Port logger running: srcPort=" + str(args.src_port) +
            " host=" + args.server + " dst=" + str(args.dst_port))

    while True:
        time.sleep(1)

    server.shutdown()
    server.server_forever()
