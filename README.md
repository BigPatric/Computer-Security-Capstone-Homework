# Computer-Security-Capstone-Homework

This repository is for the CSC-2026 homework recordings, by BigPatric (Hsin-Ze Wu)

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

The project demonstrates traffic interception in a controlled network. The
setup script enables IPv4 forwarding, flushes the NAT table, and redirects
selected HTTPS traffic to a local service on port `8080`.

- Source: [`project1/112550018-project1`](project1/112550018-project1)
- Setup: [`project1/csc2026-project1-E3/setup.sh`](project1/csc2026-project1-E3/setup.sh)
- Main entry point: [`attack.py`](project1/112550018-project1/attack.py)

Run the setup only in an isolated Linux lab environment:

```bash
cd project1/csc2026-project1-E3
sudo ./setup.sh
```

The script changes host firewall and forwarding state. Review it before
running, and restore any system networking changes after the exercise.

### Project 2: MITM and pharming attacks

This project contains DNS-over-HTTPS handling, a fake server, firewall rules,
ICMP redirect exercises, and pharming-related programs.

- Source: [`project2/112550018-project2`](project2/112550018-project2)
- Dependencies: [`requirements.txt`](project2/112550018-project2/requirements.txt)
- Notes: [`project2/112550018-project2/README.md`](project2/112550018-project2/README.md)


### Project 3: Ransomware propagation and payload

This project studies propagation behavior and payload handling in a Dockerized
attacker/victim environment. It includes the attack server, payload handler,
cracking code, worm source, and a small AES utility.

- Source: [`project3/112550018-project3`](project3/112550018-project3)
- Environment guide: [`project3/template/README.md`](project3/template/README.md)
- Docker files: [`project3/template`](project3/template)

### Project 4: CTF and binary exploitation

Project 4 contains exploit exercises and local challenge servers, including
randomness, shell, shop, return-to-flag, ROP, and agent-hacker challenges.

- Student scripts: [`project4/112550018-project4`](project4/112550018-project4)
- Challenge services: [`project4/project4-servers`](project4/project4-servers)
