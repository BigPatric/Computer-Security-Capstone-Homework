#!/usr/bin/env python3
import asyncio
from hypercorn.config import Config
from hypercorn.asyncio import serve

LISTEN_IP   = "0.0.0.0"
LISTEN_PORT = 5443
CERT_FILE   = "certificates/nycu.crt"
KEY_FILE    = "certificates/nycu.key"

FAKE_PAGE = b"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>\xe5\x9c\x8b\xe7\xab\x8b\xe9\x99\xbd\xe6\x98\x8e\xe4\xba\xa4\xe9\x80\x9a\xe5\xa4\xa7\xe5\xad\xb8</title>
  <style>
    body { font-family: sans-serif; text-align: center; padding: 60px; }
    h1   { color: #c0392b; }
    #clock { font-size: 48px; font-weight: bold; margin: 30px 0; }
    p    { color: #555; }
  </style>
</head>
<body>
  <h1>NYCU - \xe9\x80\x99\xe6\x98\xaf\xe6\x94\xbb\xe6\x93\x8a\xe9\xa0\x81\xe9\x9d\xa2</h1>
  <p>\xe4\xbd\xa0\xe5\xb7\xb2\xe8\xa2\xab pharming \xe6\x94\xbb\xe6\x93\x8a\xe5\xb0\x8e\xe5\x90\x91\xe6\xad\xa4\xe9\xa0\x81\xe9\x9d\xa2</p>
  <div id="clock"></div>
  <script>
    function updateClock() {
      document.getElementById('clock').textContent =
        new Date().toLocaleTimeString('zh-TW', { hour12: false });
    }
    updateClock();
    setInterval(updateClock, 1000);
  </script>
</body>
</html>"""

async def app(scope, receive, send):
    if scope['type'] == 'lifespan':
        while True:
            msg = await receive()
            if msg['type'] == 'lifespan.startup':
                await send({'type': 'lifespan.startup.complete'})
            elif msg['type'] == 'lifespan.shutdown':
                await send({'type': 'lifespan.shutdown.complete'})
                return
        return
    if scope['type'] != 'http':
        return

    # drain request body
    more = True
    while more:
        msg = await receive()
        more = msg.get('more_body', False)

    host = dict(scope.get('headers', [])).get(b'host', b'').decode()
    path = scope.get('path', '')
    print(f"[Web] Request: {host}{path}")

    await send({'type': 'http.response.start', 'status': 200, 'headers': [
        [b'content-type', b'text/html; charset=utf-8'],
        [b'content-length', str(len(FAKE_PAGE)).encode()],
    ]})
    await send({'type': 'http.response.body', 'body': FAKE_PAGE})

if __name__ == '__main__':
    print(f"Fake HTTPS server (HTTP/2) started")
    print(f"Listening: {LISTEN_IP}:{LISTEN_PORT}")
    print(f"Cert: {CERT_FILE}\n")
    config = Config()
    config.bind           = [f"{LISTEN_IP}:{LISTEN_PORT}"]
    config.certfile       = CERT_FILE
    config.keyfile        = KEY_FILE
    config.alpn_protocols = ["h2", "http/1.1"]
    asyncio.run(serve(app, config))

