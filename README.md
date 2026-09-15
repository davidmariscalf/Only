# Only

**Capture first. Interpret second.**

Only creates evidence capsules from public web URLs, public HTTP(S) Git repositories, and local files. It records what it actually observed, hashes every evidence artifact, and verifies capsule consistency later.

The design rule is narrow on purpose: **untrusted content is data, never code**.

## What Only protects against

Only is built to reduce accidental trust in changing or untrusted sources:

- URL requests are restricted to globally routable addresses.
- DNS is pinned to the validated address set for each HTTP hop.
- Redirects are revalidated and capped.
- Git clones use `http.curloptResolve` to pin validated DNS results.
- Git system/global configuration is ignored during acquisition.
- Repository submodules are not initialized.
- Repository symlinks are recorded but never followed.
- Capsule verification rejects symlinks, path traversal, duplicate entries, undeclared files, size drift, and hash drift.
- `diff` refuses to compare capsules that fail verification.

Only does **not** prove that a source is truthful and does not authenticate a capsule by itself. A malicious party that can replace both the evidence and its manifest can recompute the hashes. For authenticity, keep the printed `manifest_sha256` somewhere independent and later pass it to `only verify --expect`. GitHub workflow captures additionally expose a platform-computed artifact digest.

## Install

```bash
python -m pip install -e .
```

Python 3.10+ and Git are required. Only has no runtime Python dependencies.

## Capture a URL

```bash
only url https://example.com
```

The output includes raw response bytes capped at 10 MiB, duplicate-preserving HTTP headers, redirect/DNS/connected-peer/TLS facts, bounded HTML facts when applicable, a report, and a manifest with SHA-256 hashes.

Only follows at most five redirects. Every redirect destination is checked independently before a connection is made.

## Inspect a public repository

```bash
only repo https://github.com/owner/repository
```

Only performs a shallow HTTP(S) clone and records the exact HEAD commit, tracked-file count, up to 20,000 inventory entries, Git modes/object IDs, SHA-256 for regular files, symlink targets without dereferencing them, gitlinks without initializing submodules, common dependency/build manifests, and up to 500 TODO/FIXME/HACK/XXX markers.

Repository-controlled code, hooks, package managers, build scripts, tests, and submodules are not executed.

## Capture a local file

```bash
only file ./paper.pdf
```

Local symlinks are refused. The capsule contains a regular copied artifact.

## Verify

Internal consistency:

```bash
only verify captures/example
```

Externally anchored verification:

```bash
only verify captures/example --expect <saved-manifest-sha256>
```

`--expect` also accepts `sha256:<digest>` and `manifest_sha256=<digest>`. A matching external digest means replacing both the evidence and manifest cannot go unnoticed unless the independent anchor is also replaced.

Get the digest directly with:

```bash
only digest captures/example
```

## Compare two capsules

```bash
only diff captures/old captures/new
```

Both capsules must verify first. The diff output includes each manifest digest.

## Use from GitHub

### Manual workflow

Open **Actions → Only Capture → Run workflow** and provide a public URL or repository. The run summary records the manifest digest and GitHub's artifact digest.

### Owner-authored issue

Open an issue whose title begins with `[only]` and use:

```text
kind: url
target: https://example.com
label: example
```

or:

```text
kind: repo
target: https://github.com/owner/repository
label: repository
```

The issue-triggered workflow runs only for issues authored by the repository owner. The bot comment records the run URL, `manifest_sha256`, and GitHub artifact digest, giving the capsule integrity anchors outside the artifact itself.

## Capsule shape

```text
captures/<timestamp>-<label>/
├── REPORT.md
├── manifest.json
└── evidence files
```

The manifest records each evidence path, byte length, and SHA-256. The manifest's own SHA-256 is the compact capsule identifier printed by the CLI.

## Bounded acquisition

Only deliberately caps work rather than pretending every target can be exhaustively captured:

- URL body: 10 MiB
- redirects: 5
- repository inventory: 20,000 tracked entries
- marker results: 500
- HTML links: 10,000
- HTML script references: 2,000
- HTML metadata entries: 1,000

Truncation is recorded.

## Non-goals

Only is not a truth engine, browser/JavaScript renderer, full crawler, malware sandbox, vulnerability scanner, cryptographic signature system, or archival service.

Its job is smaller: acquire bounded evidence without executing target-controlled code, make the acquisition policy explicit, and make later silent drift detectable when the manifest digest is anchored externally.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the explicit boundary and remaining assumptions.
