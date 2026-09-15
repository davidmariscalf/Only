from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import OnlyError, capture_file, capture_repo, capture_url, diff_capsules, verify_capsule


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="only", description="Build and verify evidence capsules without executing untrusted code.")
    p.add_argument("--out", type=Path, default=Path("captures"), help="output root (default: captures)")
    sub = p.add_subparsers(dest="command", required=True)

    url = sub.add_parser("url", help="capture an HTTP(S) URL")
    url.add_argument("target")
    url.add_argument("--label")

    repo = sub.add_parser("repo", help="inspect a Git repository via shallow clone")
    repo.add_argument("target")
    repo.add_argument("--label")

    file = sub.add_parser("file", help="capture a local file")
    file.add_argument("target", type=Path)
    file.add_argument("--label")

    verify = sub.add_parser("verify", help="verify a capsule's evidence hashes")
    verify.add_argument("capsule", type=Path)

    diff = sub.add_parser("diff", help="compare two capsule manifests")
    diff.add_argument("left", type=Path)
    diff.add_argument("right", type=Path)
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "url":
            ref = capture_url(args.target, args.out, args.label)
            print(ref)
            return 0
        if args.command == "repo":
            ref = capture_repo(args.target, args.out, args.label)
            print(ref)
            return 0
        if args.command == "file":
            ref = capture_file(args.target, args.out, args.label)
            print(ref)
            return 0
        if args.command == "verify":
            ok, problems = verify_capsule(args.capsule)
            if ok:
                print("OK")
                return 0
            for problem in problems:
                print(problem, file=sys.stderr)
            return 1
        if args.command == "diff":
            print(json.dumps(diff_capsules(args.left, args.right), indent=2, sort_keys=True))
            return 0
    except (OnlyError, OSError, json.JSONDecodeError) as exc:
        print(f"only: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
