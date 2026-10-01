# Project 2: MITM and pharming attacks

Project 2 contains three related network attack demonstrations. They can be run independently depending on the task.

## 2A. ICMP Redirect

1. `make` compiles `icmp_redirect`, `icmp_task4`, and `pharm_attack`.
2. `icmp_redirect` scans the local `/24` network with ARP requests and lists available devices.
3. The operator selects the victim and gateway, or runs `icmp_task4` for its predefined destinations.
4. The program sends a forged ICMP Redirect so the victim changes the route for the selected destination toward the attacker.

## 2B. Traditional DNS pharming

1. `firewall.sh` enables forwarding and sends UDP/53 traffic to NFQUEUE queue `0`.
2. `pharm_attack` reads DNS packets from the queue.
3. For a query for `www.nycu.edu.tw`, it drops the original query and returns a forged A record pointing to `140.113.207.227`.
4. Other DNS packets are accepted normally.

```text
Victim DNS query
    |
    v
iptables NFQUEUE :0
    |
    v
pharm_attack
    |             |
target domain   other domains
    |             |
fake response   accept normally
```

## 2C. DoH interception and fake HTTPS server

1. `fake_server.py` starts an HTTPS/HTTP2 server on port `5443`.
2. `doh.py` configures forwarding and redirects selected HTTPS traffic to the local DoH proxy on port `4443`.
3. The DoH proxy forwards normal requests to the upstream Cloudflare DoH service.
4. For `www.nycu.edu.tw`, it changes the A record to `192.168.126.123` and returns an empty answer for AAAA queries.
5. Traffic to the forged address is redirected to `fake_server.py`, which serves the fake HTTPS page.

```text
Victim DoH request
    |
    v
iptables REDIRECT :4443
    |
    v
doh.py -----> Upstream DoH server
    |
    v
Forged IP: 192.168.126.123
    |
    v
iptables REDIRECT :5443
    |
    v
fake_server.py
```
