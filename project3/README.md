# Project 3: Ransomware Propagation and Payload

This project demonstrates propagation through a polluted command and a remotely delivered encryption payload.

## Attack workflow

1. `crack_attack.py` uses SSH/SFTP to access the victim and uploads a polluted `date` program, usually as `/app/date`.
2. The polluted `date` disguises itself as a normal date command while retaining the original `date` binary.
3. When the victim executes `/app/date`, the polluted program connects back to `attack_server.py` and requests `/worm`.
4. `PayloadHandler.py` inserts the encryption key and IV into `worm.cpp`, compiles the worm, and returns the generated binary.
5. The polluted `date` saves the downloaded worm in a temporary file and executes it.
6. The worm scans `/app/Pictures`, encrypts `.jpg` files into `.jpg.enc`, and removes the original image files.
7. After the worm finishes, the polluted program executes the original `date` behavior so the command appears to have run normally.

## Attack path

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

## Main files

- `crack_attack.py`: victim access and polluted program generation.
- `virus_template.c`: downloader, process launcher, and original `date` wrapper.
- `attack_server.py`: HTTP server that handles worm requests.
- `PayloadHandler.py`: generates and serves the worm binary.
- `worm.cpp`: image encryption payload.
