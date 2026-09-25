#!/usr/bin/env python3
"""Generate a deterministic SHA-256 manifest for the public source tree."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SKIP_DIRECTORIES = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "out", "build"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_manifest(root: Path, output: Path) -> dict:
    root = root.resolve()
    output = output.resolve()
    files = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in SKIP_DIRECTORIES for part in relative.parts):
            continue
        if not path.is_file() or path.resolve() == output:
            continue
        files.append(
            {
                "path": relative.as_posix(),
                "sha256": sha256(path),
                "size": path.stat().st_size,
            }
        )
    return {
        "schema_version": "rehostrace.source-manifest/v1",
        "file_count": len(files),
        "files": files,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    document = build_manifest(args.root, args.output)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", "files": document["file_count"], "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
