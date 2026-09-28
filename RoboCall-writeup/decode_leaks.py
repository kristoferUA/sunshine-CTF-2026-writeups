#!/usr/bin/env python3
"""Reassemble RoboCall's recorded four-byte stack leaks."""

LEAKS = (
    (0x400, 2070836595),
    (0x480, 1601531769),
    (0x520, 1953723757),
    (0x570, 1600479839),
    (0x5A0, 1701670771),
    (0x640, 1919906655),
    (0x690, 1718574964),
    (0x6C0, 1835626079),
    (0x760, 1600482402),
    (0x7B0, 1667330163),
    (0x7E0, 1634623333),
    (0x800, 1634167158),
    (0x880, 2104651636),
)


def main():
    chunks = []
    for depth, value in LEAKS:
        chunk = value.to_bytes(4, byteorder="little")
        chunks.append(chunk)
        print(f"{depth:#05x}: {value} -> {chunk!r}")

    flag = b"".join(chunks).decode("ascii")
    print(f"Flag: {flag}")


if __name__ == "__main__":
    main()
