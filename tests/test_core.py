from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from onlylab.core import OnlyError, capture_file, diff_capsules, slug, verify_capsule, _public_url
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
            self.assertTrue(any(x["path"] == "artifact.bin" and x["change"] == "modified" for x in diff["changes"]))

    def test_private_destination_rejected(self):
        with self.assertRaises(OnlyError):
            _public_url("http://127.0.0.1/")

    def test_issue_form_parser(self):
        body = "### Kind\n\nrepo\n\n### Target\n\nhttps://github.com/openai/openai-python\n\n### Label\n\nsdk"
        self.assertEqual(parse_body(body), {"kind": "repo", "target": "https://github.com/openai/openai-python", "label": "sdk"})


if __name__ == "__main__":
    unittest.main()
