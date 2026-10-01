# Computer-Security-Capstone-Homework

This repository is for the CSC-2026 homework recordings, by BigPatric (Hsin-Ze Wu)

**My codes are in the 112550018-project~ , the rest are all class materials**

## Repository layout

```text
.
├── project1/
│   ├── 112550018-project1/       # Student implementation
│   └── csc2026-project1-E3/      # Project setup and certificates
├── project2/
│   ├── 112550018-project2/       # MITM, DoH, and pharming programs
│   └── certificates/              # Local certificate material
├── project3/
│   ├── 112550018-project3/       # Propagation and payload implementation
│   └── template/                  # Docker environment and AES tool
└── project4/
    ├── 112550018-project4/       # CTF exploit scripts
    └── project4-servers/          # Dockerized challenge services
```

## Projects

### Project 1: TLS connection hijacking

Project 1 uses a local TLS proxy to intercept HTTPS traffic.

1. `setup.sh` enables IPv4 forwarding and redirects selected TCP/443 traffic to the local proxy port `8080`.
2. `attack.py` listens on port `8080` and obtains the original destination with `SO_ORIGINAL_DST`.
3. The proxy establishes a TLS connection with the victim using the local certificate, then establishes another TLS connection to the real HTTPS server.
4. Two forwarding threads relay traffic in both directions, so the victim and the real server can continue communicating.
5. The proxy inspects the login request at `/portal/api/PortalLdapLogin` andextracts the submitted `id` and `pwd` fields.

In short:

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

### Project 2: MITM and pharming attacks

Project 2 contains three related network attack demonstrations. They can be run independently depending on the task.

#### 2A. ICMP Redirect

1. `make` compiles `icmp_redirect`, `icmp_task4`, and `pharm_attack`.
2. `icmp_redirect` scans the local `/24` network with ARP requests and lists available devices.
3. The operator selects the victim and gateway, or runs `icmp_task4` for its predefined destinations.
4. The program sends a forged ICMP Redirect so the victim changes the route for the selected destination toward the attacker.

#### 2B. Traditional DNS pharming

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

#### 2C. DoH interception and fake HTTPS server

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

### Project 3: Ransomware propagation and payload

1. `crack_attack.py` uses SSH/SFTP to access the victim and uploads a polluted
    `date` program, usually as `/app/date`.
2. The polluted `date` program disguises itself as a normal date command while
    retaining the original `date` binary inside it.
3. When the victim executes `/app/date`, the polluted program connects back to
    `attack_server.py` and requests `/worm`.
4. `PayloadHandler.py` inserts the encryption key and IV into `worm.cpp`,
    compiles the worm, and returns the generated binary to the victim.
5. The polluted `date` program saves the downloaded worm in a temporary file
    and executes it.
6. The worm scans `/app/Pictures`, encrypts `.jpg` files into `.jpg.enc`, and
    removes the original image files.
7. After the worm finishes, the polluted program executes the original `date`
    behavior so the command appears to have run normally.

```text
SSH/SFTP access
        |
        v
Upload polluted /app/date
        |
        v
Victim executes date
        |
        v
Request /worm from attack_server.py
        |
        v
Download and execute generated worm
        |
        v
Encrypt victim images
```

### Project 4: CTF and binary exploitation

Read the codes in the server and tried to crack them
I've only done the:

```text

secure_random, shop, simple_shell, magicPicture, ret2flag

```

And I'm a bit lazy to explain, sorry.
