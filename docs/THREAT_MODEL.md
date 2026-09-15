# Threat model

Only exists to inspect sources that are not trusted enough to execute.

## Assets

Only tries to protect four things: files and credentials on the machine running it, private network services reachable from that machine, the integrity of captured evidence, and GitHub Actions minutes/repository permissions.

## Adversary

Assume the target URL or repository can be malicious. It may control HTTP status, headers, response bytes, redirects, DNS answers for its own hostname, repository filenames and bytes, symlinks, Git metadata/history, and pathological content designed to consume resources.

Do not assume the target controls the local operating system, Python interpreter, Git executable, CA store, GitHub platform, or the user's account. Those remain part of the trusted computing base.

## Network boundary

URL acquisition resolves every destination and refuses any resolution set containing a non-global address. The actual socket is opened against a validated address and the connected peer is checked again. Redirects are revalidated and bounded.

Git acquisition validates the destination and pins libcurl resolution with `http.curloptResolve`. Redirects are disabled. System/global Git configuration is ignored and configured HTTP proxy/credential helpers are cleared.

The public CLI and Issue entrypoints temporarily remove inherited `GIT_*`/`GCM_*`, proxy, SSH-agent, and CA-override variables before repository capture and restore them afterwards. This blocks process-level config injection such as `GIT_CONFIG_COUNT`, custom askpass helpers, or inherited network proxies on those surfaces. Direct low-level Python callers remain responsible for their process environment.

## Filesystem boundary

Submodules are never initialized. Repository symlinks are inventoried from Git metadata/filesystem link text without dereferencing them for hashing or scanning. Gitlinks are recorded as references.

Capsule manifests are untrusted input during verification. Traversal, escaping paths, symlink evidence, duplicate declarations, malformed hashes/sizes, missing evidence, and undeclared files cause verification failure.

## Integrity boundary

Every evidence file is represented in `manifest.json` by path, byte length, and SHA-256. The SHA-256 of the manifest is the compact capsule digest.

Internal verification alone cannot stop an attacker who replaces both evidence and manifest. For tamper evidence, retain the manifest digest independently and verify it later with `only verify --expect`.

GitHub Issue captures automatically write both the manifest digest and GitHub artifact digest into the issue comment. Manual captures write them to the workflow run summary.

## Resource limits

Only bounds URL bodies, redirects, repository inventory, marker results, and HTML fact collection. These limits apply after or during acquisition as documented. A Git clone can still transfer substantial data before the inventory cap is reached.

## Explicit non-goals

Only does not safely execute malware, prove a source is truthful, authenticate a human author, provide legal chain of custody, guarantee global DNS consensus, defeat a compromised local runtime, or guarantee a strict pre-transfer byte budget for Git clones.

When a safety decision is ambiguous, the intended policy is to fail closed rather than silently weaken the boundary.
