#!/usr/bin/env python3
"""Read the embedded string from the FlameOn BPS patch."""

from pathlib import Path
import sys


ROUTINE_PREFIX = bytes.fromhex(
    "5a 48 a2 00 bd 22 80 f0 09 49 5a 9f 00 c1 7e e8 80 f2 68 7a fa ab 6b"
)
XOR_KEY = 0x5A


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 1
    while True:
        if pos >= len(data):
            raise ValueError("Unexpected end of BPS data")
        byte = data[pos]
        pos += 1
        value += (byte & 0x7F) * shift
        if byte & 0x80:
            return value, pos
        shift <<= 7
        value += shift


def target_read_blocks(patch: bytes):
    if not patch.startswith(b"BPS1") or len(patch) < 16:
        raise ValueError("Not a valid BPS1 patch")

    pos = 4
    source_size, pos = read_varint(patch, pos)
    target_size, pos = read_varint(patch, pos)
    metadata_size, pos = read_varint(patch, pos)
    pos += metadata_size
    actions_end = len(patch) - 12
    target_pos = 0

    while pos < actions_end:
        command, pos = read_varint(patch, pos)
        action = command & 3
        length = (command >> 2) + 1

        if action == 1:  # TargetRead stores these bytes in the patch itself.
            end = pos + length
            if end > actions_end:
                raise ValueError("Truncated TargetRead block")
            block = patch[pos:end]
            yield target_pos, block
            pos = end
        elif action in (2, 3):  # Skip the relative offset for copy actions.
            _, pos = read_varint(patch, pos)

        target_pos += length

    if target_pos != target_size:
        raise ValueError(f"Patch actions describe {target_pos} target bytes, expected {target_size}")


def main() -> int:
    patch_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("ctf.bps")
    patch = patch_path.read_bytes()

    for target_offset, block in target_read_blocks(patch):
        if not block.startswith(ROUTINE_PREFIX):
            continue

        encoded = block[len(ROUTINE_PREFIX):].split(b"\x00", 1)[0]
        decoded = bytes(byte ^ XOR_KEY for byte in encoded)
        print(f"Literal block at target offset 0x{target_offset:x}")
        print("Ciphertext:", " ".join(f"{byte:02x}" for byte in encoded))
        print("Flag:", decoded.decode("ascii"))
        return 0

    raise ValueError("Could not find the fire-flower routine in the patch")


if __name__ == "__main__":
    raise SystemExit(main())