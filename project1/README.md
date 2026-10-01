# Project 1: TLS Connection Hijacking

This project uses a local TLS proxy to intercept selected HTTPS traffic and inspect a login request.

## Attack workflow

1. `setup.sh` enables IPv4 forwarding and redirects selected TCP port `443` traffic to the local proxy on port `8080`.
2. `attack.py` listens on port `8080` and uses `SO_ORIGINAL_DST` to determine the original destination.
3. The proxy creates a TLS server connection with the victim using the local certificate and private key.
4. It creates a second TLS client connection to the real HTTPS server.
5. Two forwarding threads relay data in both directions, allowing the victim and the real server to continue communicating through the proxy.
6. The proxy inspects the request for `/portal/api/PortalLdapLogin` and extracts the submitted `id` and `pwd` fields.

## Attack path

```text
Victim HTTPS client
        |
        v
iptables REDIRECT :8080
        |
        v
attack.py TLS proxy
        |              |
        v              v
     Victim      Real HTTPS server
```

## Main files

- `attack.py`: TLS proxy and request extraction.
- `../csc2026-project1-E3/setup.sh`: forwarding and traffic redirection rules.
