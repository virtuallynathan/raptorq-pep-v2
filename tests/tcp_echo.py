#!/usr/bin/env python3
"""Small threaded TCP echo server used by unprivileged integration tests."""

import socketserver
import sys


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data)


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


port = int(sys.argv[1])
with EchoServer(("127.0.0.1", port), EchoHandler) as server:
    server.serve_forever()
