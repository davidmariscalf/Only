# Security

Only is designed around one trust boundary: target-controlled content must not become executable code.

## Acquisition policy

For URL capture, Only accepts HTTP(S) targets whose resolved addresses are all globally routable. Connections are pinned to the validated address set, the connected peer is checked again, redirects are revalidated, and redirect depth is bounded.

For repository capture, Only accepts HTTP(S) Git URLs only. It validates the destination, pins libcurl resolution through Git's `http.curloptResolve`, disables redirects, ignores system and global Git configuration, clears configured credential helpers and HTTP proxies, disables terminal credential prompts, performs a shallow clone, and does not initialize submodules.

Repository symlinks are never dereferenced. Their link text is hashed as data. Gitlinks are recorded as Git object references without initialization.

The GitHub workflow additionally sets `GIT_ASKPASS`/`SSH_ASKPASS` to `/bin/false`, clears proxy environment variables, pins third-party Actions by commit SHA, and does not persist checkout credentials.

## Capsule verification

`only verify` treats a manifest as untrusted input. It rejects absolute or parent-traversing evidence paths, Windows-style separator tricks, evidence paths resolving outside the capsule, symlink evidence, duplicate declared paths, missing evidence, malformed byte lengths/hashes, size/hash mismatches, and undeclared files.

`only diff` verifies both capsules before comparing their manifests.

## Authenticity limitation

The manifest is an integrity description, not a signature. An attacker who can replace both the evidence and `manifest.json` can recompute all hashes. Preserve the CLI's `manifest_sha256` in an independent trusted location and use `only verify CAPSULE --expect DIGEST` when authenticity matters.

For Issue-triggered GitHub captures, the bot stores the manifest digest and GitHub's artifact digest in the issue comment. Manual workflow runs store both in the run summary. Those records are independent of the artifact contents, subject to the security of the GitHub account and platform.

## Remaining limits

Only still relies on the local Python, Git, operating system, CA trust store, process environment, and GitHub Actions runner when used there. A shallow clone can still consume significant bandwidth or disk before the bounded inventory stage. Only does not sandbox Git itself.

Local callers should treat inherited Git-specific environment variables as part of the trusted execution environment. For highly hostile acquisition, run Only inside an isolated account/container with a minimal environment.

Do not use Only as a malware execution environment. It intentionally never runs captured code.
