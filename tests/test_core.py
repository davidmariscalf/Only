from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from onlylab.core import (
    OnlyError,
    _new,
    _parse_ls_files_stage,
    _public_url,
    capsule_digest,
    capture_file,
    diff_capsules,
    slug,
    verify_capsule,
)
from onlylab.issue import parse_body


class CoreTests(unittest.TestCase):
    def test_safe_slug(self):
        self.assertEqual(slug(" Hello / World "), "hello-world")

    def test_file_capture_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "a.txt"
            src.write_text("alpha", encoding="utf-8")
            capsule = Path(capture_file(src, root / "out"))
            ok, problems = verify_capsule(capsule)
            self.assertTrue(ok)
            self.assertFalse(problems)
            original_digest = capsule_digest(capsule)
            self.assertEqual(len(original_digest), 64)

            (capsule / "artifact.bin").write_text("beta", encoding="utf-8")
            ok, problems = verify_capsule(capsule)
            self.assertFalse(ok)
            self.assertTrue(any("mismatch" in x for x in problems))

    def test_diff_capsules(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "same.txt"
            src.write_text("one", encoding="utf-8")
            a = Path(capture_file(src, root / "a"))
            src.write_text("two", encoding="utf-8")
            b = Path(capture_file(src, root / "b"))
            diff = diff_capsules(a, b)
            self.assertTrue(
                any(x["path"] == "artifact.bin" and x["change"] == "modified" for x in diff["changes"])
            )
            self.assertEqual(len(diff["left"]["manifest_sha256"]), 64)

    def test_diff_refuses_tampered_capsule(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "same.txt"
            src.write_text("one", encoding="utf-8")
            a = Path(capture_file(src, root / "a"))
            b = Path(capture_file(src, root / "b"))
            (a / "artifact.bin").write_text("tampered", encoding="utf-8")
            with self.assertRaises(OnlyError):
                diff_capsules(a, b)

    def test_private_destination_rejected(self):
        with self.assertRaises(OnlyError):
            _public_url("http://127.0.0.1/")

    def test_credentials_in_url_rejected_before_network(self):
        with self.assertRaises(OnlyError):
            _public_url("https://user:password@example.com/")

    def test_verify_rejects_manifest_path_escape(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            capsule = root / "capsule"
            capsule.mkdir()
            (capsule / "manifest.json").write_text(
                json.dumps(
                    {
                        "evidence": [
                            {
                                "path": "../outside.txt",
                                "bytes": 1,
                                "sha256": "0" * 64,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            ok, problems = verify_capsule(capsule)
            self.assertFalse(ok)
            self.assertTrue(any("unsafe evidence path" in x for x in problems))

    @unittest.skipIf(os.name == "nt", "symlink creation needs elevated privileges on some Windows runners")
    def test_verify_rejects_symlink_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            outside = root / "outside.txt"
            outside.write_text("secret", encoding="utf-8")
            capsule = root / "capsule"
            capsule.mkdir()
            link = capsule / "evidence.txt"
            link.symlink_to(outside)
            (capsule / "manifest.json").write_text(
                json.dumps(
                    {
                        "evidence": [
                            {
                                "path": "evidence.txt",
                                "bytes": len("secret"),
                                "sha256": "0" * 64,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            ok, problems = verify_capsule(capsule)
            self.assertFalse(ok)
            self.assertTrue(any("symlink evidence" in x or "escapes capsule" in x for x in problems))

    def test_duplicate_evidence_path_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "a.txt"
            src.write_text("alpha", encoding="utf-8")
            capsule = Path(capture_file(src, root / "out"))
            manifest_path = capsule / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["evidence"].append(dict(manifest["evidence"][0]))
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            ok, problems = verify_capsule(capsule)
            self.assertFalse(ok)
            self.assertTrue(any("duplicate evidence path" in x for x in problems))

    def test_unique_capture_directory_on_collision(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with mock.patch("onlylab.core.datetime") as dt:
                dt.now.return_value.strftime.return_value = "20260101T000000Z"
                first = _new(root, "same")
                second = _new(root, "same")
            self.assertNotEqual(first, second)
            self.assertTrue(second.name.endswith("-2"))

    def test_parse_ls_files_stage_handles_symlink_and_gitlink(self):
        raw = (
            b"100644 abcdef 0\tREADME.md\0"
            b"120000 123456 0\tlink\0"
            b"160000 fedcba 0\tvendor/submodule\0"
        )
        self.assertEqual(
            _parse_ls_files_stage(raw),
            [
                ("100644", "abcdef", "README.md"),
                ("120000", "123456", "link"),
                ("160000", "fedcba", "vendor/submodule"),
            ],
        )

    def test_issue_form_parser(self):
        body = (
            "### Kind\n\nrepo\n\n### Target\n\n"
            "https://github.com/openai/openai-python\n\n### Label\n\nsdk"
        )
        self.assertEqual(
            parse_body(body),
            {
                "kind": "repo",
                "target": "https://github.com/openai/openai-python",
                "label": "sdk",
            },
        )


if __name__ == "__main__":
    unittest.main()
