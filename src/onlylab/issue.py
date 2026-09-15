from __future__ import annotations

import re
import sys
from pathlib import Path

from .core import OnlyError, capsule_digest, capture_repo, capture_url

_EMPTY = {"_no response_", "no response", "none", "n/a"}


def parse_body(body: str) -> dict[str, str]:
    values: dict[str, str] = {}
    lines = body.splitlines()
    idx = 0
    while idx < len(lines):
        raw = lines[idx]
        match = re.match(r"^\s*(kind|target|label)\s*:\s*(.*?)\s*$", raw, re.I)
        if match:
            value = match.group(2).strip()
            if value and value.lower() not in _EMPTY:
                values[match.group(1).lower()] = value
            idx += 1
            continue

        heading = re.match(r"^###\s+(Kind|Target|Label)\s*$", raw, re.I)
        if heading:
            key = heading.group(1).lower()
            idx += 1
            while idx < len(lines):
                candidate = lines[idx].strip()
                if candidate.startswith("### "):
                    break
                if candidate and not candidate.startswith("<!--"):
                    if candidate.lower() not in _EMPTY:
                        values[key] = candidate
                    break
                idx += 1
            continue
        idx += 1
    return values


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    body = args[0] if args else ""
    values = parse_body(body)
    kind = values.get("kind", "url").lower()
    target = values.get("target", "")
    label = values.get("label") or None
    if not target:
        print("missing target", file=sys.stderr)
        return 2
    out = Path("captures")
    try:
        if kind == "url":
            ref = capture_url(target, out, label)
        elif kind == "repo":
            ref = capture_repo(target, out, label)
        else:
            raise OnlyError("kind must be url or repo")
    except (OnlyError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(ref)
    print(f"manifest_sha256={capsule_digest(ref)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
