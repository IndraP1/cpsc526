#!/usr/bin/python
import sys

class ProxyServer():
    def __init__(self, log_level, src_port, server, dst_port):
        self.__log_level = log_level
        self.__src_port = src_port
        self.__server = server
        self.__dst_port = dst_port

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

        proxy = ProxyServer.ProxyServer(log_level, src_port, server, dst_port)
