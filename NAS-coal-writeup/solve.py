#!/usr/bin/env python3
"""Recover the flag stored in gem_collection.pptm without opening PowerPoint."""

from __future__ import annotations

import argparse
import base64
import re
import struct
import zipfile
from pathlib import Path

FREE = 0xFFFFFFFF
END = 0xFFFFFFFE
CFB_SIGNATURE = bytes.fromhex("D0CF11E0A1B11AE1")


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def cfb_streams(data: bytes) -> dict[str, bytes]:
    """Return streams from a Compound File Binary container."""
    if data[:8] != CFB_SIGNATURE:
        raise ValueError("vbaProject.bin is not a CFB container")

    sector_size = 1 << u16(data, 30)
    mini_sector_size = 1 << u16(data, 32)
    num_fat = u32(data, 44)

    def sector(index: int) -> bytes:
        start = (index + 1) * sector_size
        return data[start:start + sector_size]

    fat_ids = [value for value in struct.unpack_from("<109I", data, 76)
               if value not in (FREE, END)]
    difat_id = u32(data, 68)
    num_difat = u32(data, 72)
    for _ in range(num_difat):
        if difat_id in (FREE, END):
            break
        values = struct.unpack("<" + "I" * (sector_size // 4), sector(difat_id))
        fat_ids.extend(value for value in values[:-1] if value not in (FREE, END))
        difat_id = values[-1]
    fat_ids = fat_ids[:num_fat]

    fat: list[int] = []
    for fat_id in fat_ids:
        fat.extend(struct.unpack("<" + "I" * (sector_size // 4), sector(fat_id)))

    def chain(start: int, table: list[int]) -> list[int]:
        result: list[int] = []
        seen: set[int] = set()
        current = start
        while current not in (FREE, END) and current < len(table) and current not in seen:
            seen.add(current)
            result.append(current)
            current = table[current]
        return result

    def read_regular(start: int, size: int | None = None) -> bytes:
        raw = b"".join(sector(index) for index in chain(start, fat))
        return raw if size is None else raw[:size]

    directory = read_regular(u32(data, 48))
    entries: list[tuple[str, int, int, int]] = []
    for offset in range(0, len(directory), 128):
        entry = directory[offset:offset + 128]
        if len(entry) < 128 or entry[66] == 0:
            continue
        name_length = u16(entry, 64)
        name = entry[:max(0, name_length - 2)].decode("utf-16le", "replace")
        start = u32(entry, 116)
        size = struct.unpack_from("<Q", entry, 120)[0]
        entries.append((name, entry[66], start, size))

    root = next((entry for entry in entries if entry[1] == 5), None)
    if root is None:
        raise ValueError("CFB root directory is missing")
    root_bytes = read_regular(root[2], root[3])

    mini_cutoff = u32(data, 56)
    mini_fat_start = u32(data, 60)
    mini_fat_count = u32(data, 64)
    mini_fat_raw = (read_regular(mini_fat_start, mini_fat_count * sector_size)
                    if mini_fat_count and mini_fat_start not in (FREE, END) else b"")
    mini_fat = list(struct.unpack("<" + "I" * (len(mini_fat_raw) // 4), mini_fat_raw))

    def read_entry(entry: tuple[str, int, int, int]) -> bytes:
        name, kind, start, size = entry
        if kind == 5:
            return root_bytes
        if size < mini_cutoff and mini_fat:
            parts: list[bytes] = []
            seen: set[int] = set()
            current = start
            while current not in (FREE, END) and current < len(mini_fat) and current not in seen:
                seen.add(current)
                begin = current * mini_sector_size
                parts.append(root_bytes[begin:begin + mini_sector_size])
                current = mini_fat[current]
            return b"".join(parts)[:size]
        return read_regular(start, size)

    return {name: read_entry(entry) for entry in entries
            for name, kind, _, _ in [entry] if kind == 2}


def decompress_vba(data: bytes) -> bytes:
    """Expand an MS-OVBA compressed container."""
    if not data or data[0] != 1:
        raise ValueError("VBA source container has an invalid header")

    cursor = 1
    output = bytearray()
    while cursor + 2 <= len(data):
        header = u16(data, cursor)
        cursor += 2
        chunk_size = (header & 0x0FFF) + 3
        chunk_end = min(len(data), cursor + chunk_size - 2)
        if (header & 0x7000) != 0x3000:
            raise ValueError("VBA source container has an invalid chunk")

        if not header & 0x8000:
            output.extend(data[cursor:chunk_end][:4096])
            cursor = chunk_end
            continue

        chunk = bytearray()
        while cursor < chunk_end and len(chunk) < 4096:
            flags = data[cursor]
            cursor += 1
            for bit in range(8):
                if cursor >= chunk_end or len(chunk) >= 4096:
                    break
                if flags & (1 << bit):
                    if cursor + 2 > chunk_end:
                        break
                    token = u16(data, cursor)
                    cursor += 2
                    offset_bits = max(4, (len(chunk) - 1).bit_length())
                    length_bits = 16 - offset_bits
                    distance = (token >> length_bits) + 1
                    count = (token & ((1 << length_bits) - 1)) + 3
                    if distance > len(chunk):
                        raise ValueError("VBA source contains an invalid copy token")
                    for _ in range(min(count, 4096 - len(chunk))):
                        chunk.append(chunk[-distance])
                else:
                    chunk.append(data[cursor])
                    cursor += 1
        output.extend(chunk)
        cursor = chunk_end
    return bytes(output)


def recover_flag(presentation: Path) -> str:
    with zipfile.ZipFile(presentation) as archive:
        project = archive.read("ppt/vbaProject.bin")

    streams = cfb_streams(project)
    directory = decompress_vba(streams["dir"])
    marker = b"\x31\x00\x04\x00\x00\x00"
    marker_at = directory.find(marker)
    if marker_at < 0:
        raise ValueError("module source offset was not found")
    source_offset = u32(directory, marker_at + len(marker))

    module = streams["MediaCache"]
    source = decompress_vba(module[source_offset:]).decode("latin1", "replace")
    match = re.search(r'(?im)^\s*encoded\s*=\s*"([A-Za-z0-9+/=]+)"', source)
    if match is None:
        raise ValueError("encoded text was not found in MediaCache")

    decoded = base64.b64decode(match.group(1), validate=True).decode("utf-16le")
    flag = re.search(r"[A-Za-z0-9_]+\{[^{}\r\n]+\}", decoded)
    if flag is None:
        raise ValueError("flag pattern was not found in decoded text")
    return flag.group(0)


def main() -> None:
    default_file = Path(__file__).parent / "challenge" / "gem_collection.pptm"
    parser = argparse.ArgumentParser(description="Recover the flag from gem_collection.pptm")
    parser.add_argument("file", nargs="?", type=Path, default=default_file)
    args = parser.parse_args()
    print(recover_flag(args.file))


if __name__ == "__main__":
    main()
