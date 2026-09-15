from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from .core import (
    OnlyError,
    capsule_digest,
    capture_file,
    capture_repo,
    capture_url,
    diff_capsules,
    verify_capsule,
)
from .environment import isolated_git_environment


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="only",
        description="Build and verify evidence capsules without executing untrusted code.",
    )
    p.add_argument("--out", type=Path, default=Path("captures"), help="output root (default: captures)")
    sub = p.add_subparsers(dest="command", required=True)

    url = sub.add_parser("url", help="capture a public HTTP(S) URL")
    url.add_argument("target")
    url.add_argument("--label")

    repo = sub.add_parser("repo", help="inspect a public HTTP(S) Git repository via shallow clone")
    repo.add_argument("target")
    repo.add_argument("--label")

    file = sub.add_parser("file", help="capture a local regular file")
    file.add_argument("target", type=Path)
    file.add_argument("--label")

    verify = sub.add_parser("verify", help="verify a capsule's declared evidence")
    verify.add_argument("capsule", type=Path)
    verify.add_argument(
        "--expect",
        metavar="SHA256",
        help="require an externally retained manifest SHA-256 to match",
    )

    digest = sub.add_parser("digest", help="print the SHA-256 digest of a capsule manifest")
    digest.add_argument("capsule", type=Path)

    diff = sub.add_parser("diff", help="compare two verified capsule manifests")
    diff.add_argument("left", type=Path)
    diff.add_argument("right", type=Path)
    return p


def _created(ref: Path) -> None:
    print(ref)
    print(f"manifest_sha256={capsule_digest(ref)}")


def _expected_digest(value: str) -> str:
    candidate = value.strip().lower()
    for prefix in ("sha256:", "manifest_sha256="):
        if candidate.startswith(prefix):
            candidate = candidate[len(prefix):].strip()
            break
    if not re.fullmatch(r"[0-9a-f]{64}", candidate):
        raise OnlyError("--expect must be a 64-character SHA-256 digest")
    return candidate


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "url":
            ref = capture_url(args.target, args.out, args.label)
            _created(ref)
            return 0
        if args.command == "repo":
            with isolated_git_environment():
                ref = capture_repo(args.target, args.out, args.label)
            _created(ref)
            return 0
        if args.command == "file":
            ref = capture_file(args.target, args.out, args.label)
            _created(ref)
            return 0
        if args.command == "verify":
            ok, problems = verify_capsule(args.capsule)
            if not ok:
                for problem in problems:
                    print(problem, file=sys.stderr)
                return 1
            actual = capsule_digest(args.capsule)
            if args.expect:
                expected = _expected_digest(args.expect)
                if actual != expected:
                    print(
                        f"manifest fingerprint mismatch: expected {expected}, got {actual}",
                        file=sys.stderr,
                    )
                    return 1
                print(f"OK manifest_sha256={actual} external_anchor=matched")
            else:
                print(f"OK manifest_sha256={actual}")
            return 0
        if args.command == "digest":
            print(capsule_digest(args.capsule))
            return 0
        if args.command == "diff":
            print(json.dumps(diff_capsules(args.left, args.right), indent=2, sort_keys=True))
            return 0
    except (OnlyError, OSError, json.JSONDecodeError) as exc:
        print(f"only: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
