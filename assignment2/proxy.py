#!/usr/bin/python
import sys
import socketserver
import threading
import time

class MyTCPHandler(socketserver.BaseRequestHandler):
    BUFFER_SIZE = 4096

def handle(self):
    try:
        while True:
            msg = self.request.recv(self.BUFFER_SIZE)
    except IOError as e:
        print("Error occured {}".format(str(e)))

if __name__ == "__main__":
    print("Starting proxy server")

    if len(sys.argv) == 5:
        log_level = sys.argv[1]
        src_port = int(sys.argv[2])
        server = sys.argv[3]
        dst_port = int(sys.argv[4])
    elif len(sys.argc) == 4:
        log_level = 'default'
        src_port = int(sys.argv[1])
        server = sys.argv[2]
        dst_port = int(sys.argv[3])

    server = socketserver.ThreadingTCPServer((server, src_port), MyTCPHandler)
    # thread = threading.Thread(target=server.serve_forever)
    thread = threading.Thread(target=server.serve_forever).start()
    # thread.daemon = True
    # thread.start()

    print("Server taking requests on port " + src_port)
    print("Server forwarding requests to port " + src_port + " of " + server)

    while True:
        time.sleep(1)

    server.shutdown()
    server.server_forever()
