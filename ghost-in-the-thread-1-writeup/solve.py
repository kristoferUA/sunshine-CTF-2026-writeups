#!/usr/bin/env python3
"""Recover the main Ghost in the Thread flag from the supplied OVA."""

import argparse
import hashlib
import math
import re
import shutil
import struct
import tarfile
import tempfile
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DEFAULT_OVA = ROOT / "challenge" / "GhostInTheThread.ova"
DECODE_KEY = b"pow1rS}K4"
KEY_FNV1A = 0xDAC3D58D
CIPHERTEXT_OFFSET = 0x2000
FLAG_LENGTH = 30


def extract_vmdk(ova_path, destination):
    """Copy the VMDK member from the OVA tar archive without extracting paths."""
    with tarfile.open(ova_path, "r:*") as archive:
        members = [
            item for item in archive.getmembers()
            if item.isfile() and item.name.lower().endswith(".vmdk")
        ]
        if len(members) != 1:
            raise ValueError("Expected exactly one VMDK in the OVA")
        source = archive.extractfile(members[0])
        if source is None:
            raise ValueError("Could not read the VMDK member")
        with source, destination.open("wb") as output:
            shutil.copyfileobj(source, output)


def expand_sparse_vmdk(vmdk_path, raw_path):
    """Expand the stream-optimized sparse VMDK into a sparse raw disk file."""
    with vmdk_path.open("rb") as image:
        header = image.read(512)
        if header[:4] != b"KDMV":
            raise ValueError("The OVA member is not a sparse VMDK")

        version, _flags = struct.unpack_from("<II", header, 4)
        capacity, grain_sectors, _descriptor_sector, _descriptor_sectors = (
            struct.unpack_from("<QQQQ", header, 12)
        )
        entries_per_table = struct.unpack_from("<I", header, 44)[0]
        overhead_sectors = struct.unpack_from("<Q", header, 64)[0]
        disk_size = capacity * 512
        grain_size = grain_sectors * 512
        entries_per_directory = math.ceil(
            capacity / (grain_sectors * entries_per_table)
        )

        with raw_path.open("wb") as raw:
            raw.truncate(disk_size)
            position = overhead_sectors * 512
            image_size = vmdk_path.stat().st_size

            while position + 12 <= image_size:
                image.seek(position)
                record = image.read(12)
                if len(record) != 12:
                    break
                sector, compressed_size = struct.unpack("<QI", record)

                if compressed_size:
                    compressed = image.read(compressed_size)
                    if len(compressed) != compressed_size:
                        raise ValueError("Truncated compressed VMDK grain")
                    grain = zlib.decompress(compressed)
                    if len(grain) > grain_size:
                        raise ValueError("VMDK grain is larger than its declared size")
                    if sector * 512 + len(grain) > disk_size:
                        raise ValueError("VMDK grain exceeds the virtual disk")
                    raw.seek(sector * 512)
                    raw.write(grain)
                    position += 12 + compressed_size
                    position = (position + 511) // 512 * 512
                    continue

                marker = image.read(4)
                if len(marker) != 4:
                    break
                marker_type = struct.unpack("<I", marker)[0]
                if marker_type == 0:
                    break
                if marker_type == 1:
                    payload_size = entries_per_table * 4
                elif marker_type == 2:
                    payload_size = entries_per_directory * 4
                elif marker_type == 3:
                    payload_size = 512
                else:
                    raise ValueError("Unknown sparse VMDK marker")
                position += 512 + ((payload_size + 511) // 512 * 512)

        return version, disk_size


def find_ext4_partition(raw_path):
    """Read GPT entries and identify the partition with an ext4 superblock."""
    with raw_path.open("rb") as disk:
        disk.seek(512)
        header = disk.read(512)
        if header[:8] != b"EFI PART":
            raise ValueError("No GPT header at LBA 1")
        entry_lba = struct.unpack_from("<Q", header, 72)[0]
        entry_count, entry_size = struct.unpack_from("<II", header, 80)
        if entry_size < 128:
            raise ValueError("Invalid GPT entry size")

        for index in range(entry_count):
            disk.seek(entry_lba * 512 + index * entry_size)
            entry = disk.read(entry_size)
            if len(entry) < 128 or entry[:16] == b"\0" * 16:
                continue
            first_lba = struct.unpack_from("<Q", entry, 32)[0]
            disk.seek(first_lba * 512 + 1024 + 56)
            if struct.unpack("<H", disk.read(2))[0] == 0xEF53:
                return first_lba
    raise ValueError("No ext4 partition found in the GPT")


class Ext4Reader:
    """Minimal read-only ext4 reader for the uncompressed extents in this image."""

    def __init__(self, path, partition_lba):
        self.disk = path.open("rb")
        self.base = partition_lba * 512
        self.superblock = self.read_at(self.base + 1024, 1024)
        if len(self.superblock) != 1024:
            raise ValueError("Truncated ext4 superblock")
        if struct.unpack_from("<H", self.superblock, 56)[0] != 0xEF53:
            raise ValueError("Invalid ext4 superblock")

        sb = self.superblock
        self.inode_count = struct.unpack_from("<I", sb, 0)[0]
        self.block_count = struct.unpack_from("<I", sb, 4)[0]
        self.first_data_block = struct.unpack_from("<I", sb, 20)[0]
        self.block_size = 1024 << struct.unpack_from("<I", sb, 24)[0]
        self.blocks_per_group = struct.unpack_from("<I", sb, 32)[0]
        self.inodes_per_group = struct.unpack_from("<I", sb, 40)[0]
        self.revision = struct.unpack_from("<I", sb, 76)[0]
        self.inode_size = struct.unpack_from("<H", sb, 88)[0] if self.revision else 128
        self.incompat = struct.unpack_from("<I", sb, 96)[0]
        if self.incompat & 0x80:
            self.block_count |= struct.unpack_from("<I", sb, 336)[0] << 32
        self.desc_size = struct.unpack_from("<H", sb, 254)[0]
        if self.desc_size < 32:
            self.desc_size = 32
        self.gdt_offset = self.base + (self.first_data_block + 1) * self.block_size

    def read_at(self, offset, size):
        self.disk.seek(offset)
        return self.disk.read(size)

    def inode(self, number):
        if number < 1 or number > self.inode_count:
            return None
        group = (number - 1) // self.inodes_per_group
        index = (number - 1) % self.inodes_per_group
        desc = self.read_at(self.gdt_offset + group * self.desc_size, self.desc_size)
        if len(desc) < 32:
            return None
        inode_table = struct.unpack_from("<I", desc, 8)[0]
        if self.desc_size >= 64:
            inode_table |= struct.unpack_from("<I", desc, 40)[0] << 32
        offset = self.base + inode_table * self.block_size + index * self.inode_size
        raw = self.read_at(offset, self.inode_size)
        if len(raw) < 128:
            return None

        mode = struct.unpack_from("<H", raw, 0)[0]
        size = struct.unpack_from("<I", raw, 4)[0]
        if mode & 0xF000 == 0x8000:
            size |= struct.unpack_from("<I", raw, 108)[0] << 32
        return {
            "number": number,
            "mode": mode,
            "size": size,
            "flags": struct.unpack_from("<I", raw, 32)[0],
            "block_data": raw[40:100],
        }

    def extent_blocks(self, data):
        if len(data) < 12 or struct.unpack_from("<H", data, 0)[0] != 0xF30A:
            return []
        count = struct.unpack_from("<H", data, 2)[0]
        depth = struct.unpack_from("<H", data, 6)[0]
        blocks = []
        offset = 12
        for _ in range(count):
            if depth == 0:
                logical, length, start_hi, start_lo = struct.unpack_from(
                    "<IHHI", data, offset
                )
                length &= 0x7FFF
                physical = (start_hi << 32) | start_lo
                blocks.extend((logical + i, physical + i) for i in range(length))
            else:
                _logical, leaf_lo, leaf_hi = struct.unpack_from("<IIH", data, offset)
                leaf = (leaf_hi << 32) | leaf_lo
                child = self.read_at(self.base + leaf * self.block_size, self.block_size)
                blocks.extend(self.extent_blocks(child))
            offset += 12
        return blocks

    def file_bytes(self, inode):
        if inode["size"] == 0:
            return b""
        if not inode["flags"] & 0x80000:
            raise ValueError("Encountered a file without ext4 extents")
        extents = dict(self.extent_blocks(inode["block_data"]))
        result = bytearray()
        block_count = math.ceil(inode["size"] / self.block_size)
        for logical in range(block_count):
            physical = extents.get(logical)
            if physical is None:
                result.extend(b"\0" * self.block_size)
            else:
                result.extend(
                    self.read_at(self.base + physical * self.block_size, self.block_size)
                )
        return bytes(result[:inode["size"]])

    def directory_entries(self, inode):
        data = self.file_bytes(inode)
        offset = 0
        while offset + 8 <= len(data):
            number = struct.unpack_from("<I", data, offset)[0]
            record_len = struct.unpack_from("<H", data, offset + 4)[0]
            name_len = data[offset + 6]
            if record_len < 8 or offset + record_len > len(data):
                break
            if number:
                name = data[offset + 8:offset + 8 + name_len].decode(
                    "utf-8", errors="replace"
                )
                yield number, name
            offset += record_len

    def walk_files(self):
        files = {}
        pending = [(2, "")]
        visited = set()
        while pending:
            number, prefix = pending.pop()
            if number in visited:
                continue
            visited.add(number)
            inode = self.inode(number)
            if inode is None or inode["mode"] & 0xF000 != 0x4000:
                continue
            for child_number, name in self.directory_entries(inode):
                if name in (".", ".."):
                    continue
                path = (prefix + "/" + name) if prefix else "/" + name
                child = self.inode(child_number)
                if child is None:
                    continue
                kind = child["mode"] & 0xF000
                if kind == 0x4000:
                    pending.append((child_number, path))
                elif kind == 0x8000:
                    files[path] = child
        return files


def postscript_field(document, name):
    pattern = rb"^%%" + re.escape(name.encode("ascii")) + rb":[ \t]*(.*?)[ \t]*$"
    match = re.search(pattern, document, re.MULTILINE)
    if not match:
        raise ValueError("Missing PostScript metadata field: " + name)
    return match.group(1).decode("ascii")


def fnv1a(data):
    value = 0x811C9DC5
    for byte in data:
        value = ((value ^ byte) * 0x01000193) & 0xFFFFFFFF
    return value


def recover_flag(ova_path):
    with tempfile.TemporaryDirectory(prefix="ghost-thread-") as temporary:
        temporary = Path(temporary)
        vmdk_path = temporary / "disk.vmdk"
        raw_path = temporary / "disk.raw"
        extract_vmdk(ova_path, vmdk_path)
        _version, disk_size = expand_sparse_vmdk(vmdk_path, raw_path)

        partition_lba = find_ext4_partition(raw_path)
        filesystem = Ext4Reader(raw_path, partition_lba)
        files = filesystem.walk_files()

        upload_path = "/srv/sunchan/uploads/po_184726.pdf"
        if upload_path not in files:
            raise ValueError("Could not find the referenced upload in ext4")

        disguised_pdf = filesystem.file_bytes(files[upload_path])
        if not disguised_pdf.startswith(b"%!PS-Adobe-"):
            raise ValueError("The referenced upload is not the expected PostScript file")

        document_id = postscript_field(disguised_pdf, "Document-ID")
        if document_id != "po-184726":
            raise ValueError("Unexpected upload document ID")
        destination = postscript_field(disguised_pdf, "Stage2-Destination")
        payload_path = destination
        if payload_path not in files:
            raise ValueError("Could not find the stage-two payload in ext4")
        payload = filesystem.file_bytes(files[payload_path])

        expected_sha256 = postscript_field(disguised_pdf, "Stage2-SHA256").lower()
        actual_sha256 = hashlib.sha256(payload).hexdigest()
        if actual_sha256 != expected_sha256:
            raise ValueError("Stage-two SHA-256 does not match the upload metadata")
        if fnv1a(DECODE_KEY) != KEY_FNV1A:
            raise ValueError("The payload decoding key does not pass its FNV-1a check")

        end = CIPHERTEXT_OFFSET + FLAG_LENGTH
        if len(payload) < end:
            raise ValueError("The stage-two payload is too short")
        ciphertext = payload[CIPHERTEXT_OFFSET:end]
        plaintext = bytes(
            byte ^ DECODE_KEY[index % len(DECODE_KEY)] ^ 0x5A
            for index, byte in enumerate(ciphertext)
        )
        if not plaintext.startswith(b"sun{") or not plaintext.endswith(b"}"):
            raise ValueError("Decoded payload does not look like a SunshineCTF flag")
        return plaintext.decode("ascii"), disk_size, partition_lba


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "ova",
        nargs="?",
        type=Path,
        default=DEFAULT_OVA,
        help="challenge OVA (default: challenge/GhostInTheThread.ova)",
    )
    args = parser.parse_args()
    flag, disk_size, partition_lba = recover_flag(args.ova)
    print("Virtual disk: {} bytes".format(disk_size))
    print("ext4 partition starts at LBA {}".format(partition_lba))
    print("Flag: {}".format(flag))


if __name__ == "__main__":
    main()

