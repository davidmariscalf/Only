# Only

**Capture first. Interpret second.**

Only builds small, tamper-evident evidence capsules from a web URL, a public Git repository, or a local file. It records what it actually saw, hashes every evidence file, and can later verify that the capsule has not drifted.

The constraint that shaped the project is deliberate: **inspect untrusted things without executing them**. Repository capture never runs project code, package managers, build scripts, hooks, tests, or submodules.

## Why this exists

Research, debugging and AI-assisted work often collapse three different things into one:

1. what a source actually contained,
2. what a tool inferred from it,
3. what a person or model concluded.

Only preserves step 1 in a boring, inspectable form so steps 2 and 3 can be challenged later.

This is not a truth engine, vulnerability scanner, crawler, or malware sandbox. It is an evidence capture and provenance utility.

## Install

```bash
python -m pip install -e .
```

Python 3.10+ and Git are enough. The package has no runtime Python dependencies.

## Use

### Capture a URL

```bash
only url https://example.com
```

The capsule includes the raw response body, headers, DNS data, TLS certificate fingerprint when applicable, parsed HTML facts, a human-readable report, and a manifest containing SHA-256 hashes.

### Inspect a public repository without running it

```bash
only repo https://github.com/owner/repository
```

Only makes a shallow clone, does **not** initialize submodules, inventories files and hashes, detects common dependency/build manifests, and records TODO/FIXME/HACK/XXX markers. It executes none of the repository's code.

### Capture a local artifact

```bash
only file ./paper.pdf
```

### Verify a capsule

```bash
only verify captures/20260915T202300Z-example.com
```

Any changed, missing, or undeclared evidence file makes verification fail.

### Compare two captures

```bash
only diff captures/old captures/new
```

This reports added, removed, and modified evidence artifacts from their manifests.

## Use it from GitHub without changing the repository

There are two preconfigured paths:

- **Actions → Only Capture → Run workflow** for a URL or public repository.
- Open an owner-authored issue whose title begins with `[only]` and whose body contains:

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

The issue-triggered workflow is intentionally restricted to the repository owner so a public issue cannot be used to burn Actions minutes. Captures are uploaded as workflow artifacts and the issue receives the run link.

## Capsule shape

```text
captures/<timestamp>-<label>/
├── REPORT.md
├── manifest.json
├── ... evidence files ...
```

`manifest.json` is the trust anchor for the capsule: it lists every evidence file, its byte length, and its SHA-256 digest. `only verify` recalculates all of them and rejects undeclared files.

## Design rules

- **No remote code execution by design.** A cloned repository is data, never a program.
- **No hidden AI step.** Only captures facts and leaves interpretation explicit.
- **No API keys required.** The default workflows use only GitHub-provided infrastructure.
- **Bounded acquisition.** URL bodies are capped at 10 MiB; repository inventory is capped at 20,000 files; large files are not text-scanned.
- **Useful failure.** Network and TLS facts are recorded separately so partial captures remain understandable.

## Limits

A hash proves that a file did not change after the manifest was produced; it does not prove that the source was truthful. DNS and TLS observations are point-in-time network observations. Dynamic pages may return different content to different clients. Repository capture sees one shallow HEAD snapshot. Only does not render JavaScript or crawl linked pages.

Those limits are features as much as omissions: the tool tries to make a narrow promise it can actually keep.
