#!/usr/bin/env python3
"""Restore scanlines hidden below the declared height in hereyougo.png."""

from __future__ import annotations

import argparse
import struct
import zlib
from pathlib import Path

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def read_chunks(data: bytes) -> list[tuple[bytes, bytes]]:
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("Input is not a PNG file")

    chunks: list[tuple[bytes, bytes]] = []
    position = len(PNG_SIGNATURE)
    while position + 12 <= len(data):
        length = struct.unpack_from(">I", data, position)[0]
        chunk_type = data[position + 4 : position + 8]
        start = position + 8
        end = start + length
        if end + 4 > len(data):
            raise ValueError("Incomplete PNG chunk")
        chunks.append((chunk_type, data[start:end]))
        position = end + 4
        if chunk_type == b"IEND":
            return chunks
    raise ValueError("PNG has no complete IEND chunk")


def make_png(chunks: list[tuple[bytes, bytes]]) -> tuple[bytes, int, int, int]:
    header = next((payload for kind, payload in chunks if kind == b"IHDR"), None)
    if header is None or len(header) != 13:
        raise ValueError("PNG is missing a valid IHDR chunk")

    width, height, bit_depth, color_type, compression, filtering, interlace = (
        struct.unpack(">IIBBBBB", header)
    )
    if (bit_depth, color_type, compression, filtering, interlace) != (8, 6, 0, 0, 0):
        raise ValueError("This solver expects an 8-bit, non-interlaced RGBA PNG")

    compressed = b"".join(payload for kind, payload in chunks if kind == b"IDAT")
    decoded = zlib.decompress(compressed)
    row_size = 1 + width * 4
    visible_size = height * row_size
    if len(decoded) < visible_size:
        raise ValueError("PNG data ends before the declared image height")

    extra_size = len(decoded) - visible_size
    extra_rows, remainder = divmod(extra_size, row_size)
    if not extra_rows or remainder:
        raise ValueError("Extra data does not contain complete image rows")

    extra = decoded[visible_size:]
    if any(extra[row * row_size] > 4 for row in range(extra_rows)):
        raise ValueError("An extra row has an invalid PNG filter type")

    recovered_height = height + extra_rows
    output = bytearray(PNG_SIGNATURE)
    for kind, payload in chunks:
        if kind == b"IHDR":
            payload = bytearray(payload)
            payload[4:8] = struct.pack(">I", recovered_height)
            payload = bytes(payload)
        output.extend(struct.pack(">I", len(payload)))
        output.extend(kind)
        output.extend(payload)
        output.extend(struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF))

    return bytes(output), width, height, recovered_height


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "image",
        nargs="?",
        type=Path,
        default=Path(__file__).parent / "challenge" / "hereyougo.png",
    )
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    chunks = read_chunks(args.image.read_bytes())
    recovered, width, old_height, new_height = make_png(chunks)
    output_path = args.output or args.image.with_name("hereyougo_unclipped.png")
    output_path.write_bytes(recovered)
    print(f"Declared dimensions: {width} x {old_height}")
    print(f"Recovered dimensions: {width} x {new_height}")
    print(f"Wrote {output_path}")


if __name__ == "__main__":
    main()
