#!/usr/bin/env python3

import sys
import socketserver
from PayloadHandler import PayloadHandler

if len(sys.argv) != 2:
    print("Usage: ./attack_server <Attacker port>")
    sys.exit(1)

try:
    PORT = int(sys.argv[1])
except ValueError:
    print("[-] Error: Port 必須是整數")
    sys.exit(1)

with socketserver.ThreadingTCPServer(("", PORT), PayloadHandler) as httpd:
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()