# Security

Only is designed around one trust boundary: target-controlled content must not become executable code.

## Acquisition policy

For URL capture, Only accepts HTTP(S) targets whose resolved addresses are all globally routable. Connections are pinned to the validated address set, the connected peer is checked again, redirects are revalidated, and redirect depth is bounded.

For repository capture, Only accepts HTTP(S) Git URLs only. It validates the destination, pins libcurl resolution through Git's `http.curloptResolve`, disables redirects, ignores system and global Git configuration, clears credential helpers and HTTP proxies, disables terminal credential prompts, performs a shallow clone, and does not initialize submodules.

Repository symlinks are never dereferenced. Their link text is hashed as data. Gitlinks are recorded as Git object references without initialization.

## Capsule verification

`only verify` treats a manifest as untrusted input. It rejects:

- absolute or parent-traversing evidence paths
- Windows-style separator tricks
- evidence paths resolving outside the capsule
- symlink evidence
- duplicate declared paths
- missing evidence
- malformed byte lengths or hashes
- size/hash mismatches
- undeclared files

`only diff` verifies both capsules before comparing their manifests.

## Authenticity limitation

The manifest is an integrity description, not a signature. An attacker who can replace both the evidence and `manifest.json` can recompute all hashes. Preserve the CLI's `manifest_sha256` in an independent trusted location when authenticity matters. GitHub-hosted workflow artifacts additionally expose a platform-computed artifact digest.

## Remaining limits

Only still relies on the local Python, Git, operating system, CA trust store, GitHub Actions runner when used there, and the security of those components. A shallow clone can still consume significant bandwidth or disk before the bounded inventory stage. Only does not sandbox Git itself.

Do not use Only as a malware execution environment. It intentionally never runs captured code.
