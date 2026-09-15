from __future__ import annotations

import os
from contextlib import contextmanager
from collections.abc import Iterator

_RISKY_EXACT = {
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "CURL_CA_BUNDLE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
}


def _is_risky_git_env(key: str) -> bool:
    upper = key.upper()
    return upper.startswith("GIT_") or upper.startswith("GCM_") or upper in _RISKY_EXACT


@contextmanager
def isolated_git_environment() -> Iterator[None]:
    """Temporarily remove process-level Git/network overrides for acquisition.

    This protects the CLI and GitHub-Issue entrypoints from inherited Git config,
    credential, proxy, SSH-agent and CA override variables. Unrelated environment
    variables are left untouched and all removed values are restored afterwards.
    """

    original = {key: value for key, value in os.environ.items() if _is_risky_git_env(key)}
    for key in list(original):
        os.environ.pop(key, None)

    os.environ.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "Never",
        }
    )

    try:
        yield
    finally:
        for key in [key for key in os.environ if _is_risky_git_env(key)]:
            os.environ.pop(key, None)
        os.environ.update(original)
