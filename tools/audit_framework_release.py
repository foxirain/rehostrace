#!/usr/bin/env python3
"""Fail-closed audit for the source-only public framework tree."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


REQUIRED = {
    ".gitignore",
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CITATION.cff",
    "pyproject.toml",
}

SKIP_DIRECTORIES = {
    ".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "build", "out", ".toolcache",
}
FORBIDDEN_DIRECTORIES = {"private"}
FORBIDDEN_SUFFIXES = {
    ".o", ".a", ".so", ".ko", ".mod", ".cmd", ".cpio", ".img", ".bin",
    ".dtb", ".pcap", ".pcapng", ".btsnoop", ".log", ".zip", ".gz",
}
FORBIDDEN_FILENAMES = {"Module.symvers", "modules.order", "Module.markers"}
TEXT_SUFFIXES = {
    "", ".c", ".h", ".py", ".json", ".jsonl", ".md", ".toml", ".cff",
    ".gitignore", ".txt", ".yml", ".yaml", ".svg",
}


def decoded(hex_value: str) -> str:
    return bytes.fromhex(hex_value).decode("ascii")


FORBIDDEN_TEXT = {
    decoded("73616d73756e67"),
    decoded("67616c617879207761746368"),
    decoded("72393430"),
    decoded("637a6635"),
    decoded("73637363"),
    decoded("6b6e6f78"),
    decoded("2f686f6d652f"),
    decoded("2f55736572732f"),
}
MODEL_RE = re.compile(decoded("736d2d72") + r"\d{3,4}", re.IGNORECASE)
ADDRESS_RE = re.compile(r"\b[0-9A-Fa-f]{2}" + r":[0-9A-Fa-f]{2}" * 5 + r"\b")
PEM_RE = re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")


def iter_release_files(root: Path):
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in SKIP_DIRECTORIES for part in relative.parts):
            continue
        if path.is_file() or path.is_symlink():
            yield path, relative


def audit(root: Path) -> dict:
    root = root.resolve()
    errors: list[dict] = []
    scanned = 0
    for required in sorted(REQUIRED):
        if not (root / required).is_file():
            errors.append({"kind": "missing-required-file", "path": required})
    ignore_text = (root / ".gitignore").read_text(encoding="utf-8") if (root / ".gitignore").is_file() else ""
    for generated_directory in ("build/", "out/", ".toolcache/"):
        if generated_directory not in ignore_text:
            errors.append(
                {"kind": "generated-directory-not-ignored", "path": generated_directory}
            )

    for path, relative in iter_release_files(root):
        scanned += 1
        portable = relative.as_posix()
        if path.is_symlink():
            errors.append({"kind": "symlink-not-allowed", "path": portable})
            continue
        if any(part.lower() in FORBIDDEN_DIRECTORIES for part in relative.parts):
            errors.append({"kind": "forbidden-directory", "path": portable})
        if path.name in FORBIDDEN_FILENAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            errors.append({"kind": "generated-or-binary-artifact", "path": portable})
        if path.stat().st_size > 2 * 1024 * 1024:
            errors.append({"kind": "oversized-release-file", "path": portable})
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"Makefile", "LICENSE"}:
            errors.append({"kind": "unreviewed-file-type", "path": portable})
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append({"kind": "non-text-release-file", "path": portable})
            continue
        lowered = text.lower()
        for marker in sorted(FORBIDDEN_TEXT):
            if marker.lower() in lowered:
                errors.append({"kind": "target-or-host-marker", "path": portable})
                break
        if MODEL_RE.search(text):
            errors.append({"kind": "product-model-marker", "path": portable})
        if ADDRESS_RE.search(text):
            errors.append({"kind": "hardware-address", "path": portable})
        if PEM_RE.search(text):
            errors.append({"kind": "private-key-material", "path": portable})

    return {
        "schema_version": "rehostrace.framework-release-audit/v1",
        "status": "passed" if not errors else "failed",
        "root": ".",
        "files_scanned": scanned,
        "error_count": len(errors),
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = audit(args.root)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
