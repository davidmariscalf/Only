from __future__ import annotations

import os
import unittest
from unittest import mock

from onlylab.environment import isolated_git_environment


class EnvironmentTests(unittest.TestCase):
    def test_git_environment_is_scrubbed_and_restored(self):
        injected = {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.extraHeader",
            "GIT_CONFIG_VALUE_0": "Authorization: secret",
            "GIT_ASKPASS": "/tmp/evil-askpass",
            "GIT_SSH_COMMAND": "evil-ssh",
            "HTTPS_PROXY": "http://127.0.0.1:9999",
            "SSL_CERT_FILE": "/tmp/evil-ca.pem",
            "SSH_AUTH_SOCK": "/tmp/evil-agent",
        }
        with mock.patch.dict(os.environ, injected, clear=False):
            with isolated_git_environment():
                for key in injected:
                    self.assertNotIn(key, os.environ)
                self.assertEqual(os.environ["GIT_CONFIG_NOSYSTEM"], "1")
                self.assertEqual(os.environ["GIT_CONFIG_SYSTEM"], os.devnull)
                self.assertEqual(os.environ["GIT_CONFIG_GLOBAL"], os.devnull)
                self.assertEqual(os.environ["GIT_TERMINAL_PROMPT"], "0")
                self.assertEqual(os.environ["GCM_INTERACTIVE"], "Never")

            for key, value in injected.items():
                self.assertEqual(os.environ.get(key), value)


if __name__ == "__main__":
    unittest.main()
