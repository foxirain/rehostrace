#!/usr/bin/env python3
"""Build a byte-reproducible uncompressed SVR4 newc initramfs archive."""

from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path

TRAILER = "TRAILER!!!"


def _pad4(value: int) -> int:
    return (-value) & 3


def _field(value: int) -> bytes:
    if value < 0 or value > 0xFFFFFFFF:
        raise ValueError(f"newc field out of range: {value}")
    return f"{value:08x}".encode("ascii")


def _entry(name: str, mode: int, data: bytes, ino: int) -> bytes:
    encoded_name = name.encode("utf-8") + b"\0"
    header = b"070701" + b"".join(
        _field(value)
        for value in (
            ino,
            mode,
            0,
            0,
            2 if stat.S_ISDIR(mode) else 1,
            0,
            len(data),
            0,
            0,
            0,
            0,
            len(encoded_name),
            0,
        )
    )
    name_padding = b"\0" * _pad4(len(header) + len(encoded_name))
    data_padding = b"\0" * _pad4(len(data))
    return header + encoded_name + name_padding + data + data_padding


def build_archive(root: Path) -> bytes:
    root = root.resolve(strict=True)
    entries: list[tuple[str, int, bytes]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            entries.append((relative, stat.S_IFDIR | 0o755, b""))
        elif stat.S_ISREG(info.st_mode):
            permissions = 0o755 if info.st_mode & 0o111 else 0o644
            entries.append((relative, stat.S_IFREG | permissions, path.read_bytes()))
        else:
            raise ValueError(f"unsupported initramfs entry type: {path}")

    archive = bytearray()
    for ino, (name, mode, data) in enumerate(entries, start=1):
        archive.extend(_entry(name, mode, data, ino))
    archive.extend(_entry(TRAILER, stat.S_IFREG, b"", len(entries) + 1))
    return bytes(archive)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = build_archive(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(payload)
    print(f"wrote {args.output} ({len(payload)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
