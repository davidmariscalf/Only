from __future__ import annotations

import re
import sys
from pathlib import Path

from .core import OnlyError, capture_repo, capture_url


def parse_body(body: str) -> dict[str, str]:
    values: dict[str, str] = {}
    lines = body.splitlines()
    for idx, raw in enumerate(lines):
        match = re.match(r"^\s*(kind|target|label)\s*:\s*(.*?)\s*$", raw, re.I)
        if match:
            values[match.group(1).lower()] = match.group(2)
            continue
        heading = re.match(r"^###\s+(Kind|Target|Label)\s*$", raw, re.I)
        if heading:
            for candidate in lines[idx + 1:]:
                candidate = candidate.strip()
                if candidate and not candidate.startswith("<!--"):
                    values[heading.group(1).lower()] = candidate
                    break
    return values


def main(argv: list[str] | None = None) -> int:
    body = (argv or sys.argv[1:])[0] if (argv or sys.argv[1:]) else ""
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
    except OnlyError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(ref)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
