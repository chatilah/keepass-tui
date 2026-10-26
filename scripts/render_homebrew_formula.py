#!/usr/bin/env python3
"""Render a Homebrew formula using release checksums."""

import argparse
import re
from pathlib import Path


def read_checksum(path: Path) -> str:
    checksum = path.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", checksum):
        raise ValueError(f"Expected a SHA-256 checksum in {path}")
    return checksum.lower()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", help="release tag, such as v0.1.0")
    parser.add_argument("arm64_checksum", type=Path)
    parser.add_argument("x86_64_checksum", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if not re.fullmatch(r"v\d+\.\d+\.\d+", args.tag):
        parser.error("tag must use the vMAJOR.MINOR.PATCH format")

    template_path = Path(__file__).resolve().parents[1] / "Formula/keepass-tui.rb.template"
    formula = template_path.read_text(encoding="utf-8")
    formula = formula.replace("@@VERSION@@", args.tag[1:])
    formula = formula.replace("@@ARM64_SHA256@@", read_checksum(args.arm64_checksum))
    formula = formula.replace("@@X86_64_SHA256@@", read_checksum(args.x86_64_checksum))
    args.output.write_text(formula, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
