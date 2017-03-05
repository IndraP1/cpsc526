#!/usr/bin/python
import argparse
import socket
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--command', type=str, help='', required=True)
parser.add_argument('--filename', type=str, help='', required=True)
parser.add_argument('--hostname', type=str, help='', required=True)
parser.add_argument('--port', type=int, help='', required=True)
# parser.add_argument('--cipher', type=str, help='', required=False) #True
parser.add_argument('--key', type=str, help='', required=False)
args = parser.parse_args()


class MyTCPConnection():
    BUFFER = 4096

    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((args.hostname, args.port))

    def run(self):
        try:
            # establish connection
            # send request
            self.generate_request()
            while True:
                msg = self.receive()
                if len(msg) == 0:
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

    def send(self, msg):
        self.client_socket.sendall(bytes(msg + '\n', 'utf-8'))

    def receive(self):
        msg = self.client_socket.recv(self.BUFFER).decode('utf-8').rstrip('\n')
        return msg

    def stop(self):
        self.client_socket.close()
        exit()

if __name__ == "__main__":
    print(args)
    connection = MyTCPConnection()
    connection.run()
