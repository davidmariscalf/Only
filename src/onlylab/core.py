from __future__ import annotations

import hashlib, ipaddress, json, os, re, shutil, socket, ssl, subprocess, tempfile
import urllib.error, urllib.parse, urllib.request
from collections import Counter
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

MAX_BODY = 10 * 1024 * 1024
MAX_FILES = 20_000
USER_AGENT = "Only/0.1 (+https://github.com/davidmariscalf/Only)"


class OnlyError(RuntimeError):
    pass


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._").lower()[:80] or "capture"


def _json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def _public_url(url: str) -> urllib.parse.ParseResult:
    p = urllib.parse.urlparse(url)
    if p.scheme not in {"http", "https"} or not p.hostname:
        raise OnlyError("target must be a public http(s) URL")
    try:
        addresses = {x[4][0].split("%", 1)[0] for x in socket.getaddrinfo(p.hostname, None)}
    except socket.gaierror as e:
        raise OnlyError(f"cannot resolve {p.hostname}") from e
    if not addresses:
        raise OnlyError(f"cannot resolve {p.hostname}")
    for raw in addresses:
        try:
            if not ipaddress.ip_address(raw).is_global:
                raise OnlyError(f"refusing non-public destination: {p.hostname} -> {raw}")
        except ValueError:
            pass
    return p


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _public_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Facts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.title_bits: list[str] = []
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms = 0
        self.meta: dict[str, str] = {}

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "title": self.in_title = True
        elif tag == "a" and a.get("href"): self.links.append(a["href"])
        elif tag == "script" and a.get("src"): self.scripts.append(a["src"])
        elif tag == "form": self.forms += 1
        elif tag == "meta":
            k = a.get("name") or a.get("property")
            if k and a.get("content"): self.meta[k.lower()] = a["content"]

    def handle_endtag(self, tag):
        if tag.lower() == "title": self.in_title = False

    def handle_data(self, data):
        if self.in_title: self.title_bits.append(data)

    @property
    def title(self):
        return " ".join("".join(self.title_bits).split())


def _new(root: Path, label: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = root / f"{stamp}-{slug(label)}"
    out.mkdir()
    return out


def _finish(out: Path, manifest: dict[str, Any]) -> Path:
    manifest["evidence"] = [
        {"path": str(p.relative_to(out)).replace(os.sep, "/"), "bytes": p.stat().st_size, "sha256": sha(p)}
        for p in sorted(out.rglob("*")) if p.is_file() and p.name != "manifest.json"
    ]
    _json(out / "manifest.json", manifest)
    return out


def _net(host: str, https: bool) -> dict[str, Any]:
    result: dict[str, Any] = {"dns": sorted({x[4][0] for x in socket.getaddrinfo(host, None)})}
    if https:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=5) as s, ctx.wrap_socket(s, server_hostname=host) as t:
                result["tls"] = {
                    "protocol": t.version(),
                    "cipher": t.cipher()[0] if t.cipher() else None,
                    "certificate_sha256": hashlib.sha256(t.getpeercert(binary_form=True)).hexdigest(),
                }
        except Exception as e:
            result["tls_error"] = f"{type(e).__name__}: {e}"
    return result


def capture_url(url: str, root: Path, label: str | None = None) -> Path:
    p = _public_url(url)
    out = _new(root, label or p.hostname or "url")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with urllib.request.build_opener(SafeRedirect()).open(req, timeout=20) as r:
            raw = r.read(MAX_BODY + 1); final = r.geturl(); status = getattr(r, "status", None); headers = dict(r.headers.items())
    except urllib.error.HTTPError as e:
        raw = e.read(MAX_BODY + 1); final = e.geturl(); status = e.code; headers = dict(e.headers.items())
    except Exception as e:
        shutil.rmtree(out, ignore_errors=True)
        raise OnlyError(f"fetch failed: {type(e).__name__}: {e}") from e
    truncated = len(raw) > MAX_BODY
    body = raw[:MAX_BODY]
    (out / "response.body").write_bytes(body)
    _json(out / "headers.json", {str(k).lower(): str(v) for k, v in headers.items()})
    fp = urllib.parse.urlparse(final)
    _json(out / "network.json", _net(fp.hostname or p.hostname or "", fp.scheme == "https"))
    ctype = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
    title = ""
    if "html" in ctype.lower() or body.lstrip().lower().startswith((b"<!doctype html", b"<html")):
        text = body.decode("utf-8", errors="replace")
        parser = Facts(); parser.feed(text); title = parser.title
        _json(out / "html_facts.json", {
            "title": title, "meta": parser.meta, "forms": parser.forms,
            "links": sorted({urllib.parse.urljoin(final, x) for x in parser.links}),
            "scripts": sorted({urllib.parse.urljoin(final, x) for x in parser.scripts}),
        })
    digest = hashlib.sha256(body).hexdigest()
    (out / "REPORT.md").write_text(
        f"# Only URL capture\n\n- Requested: `{url}`\n- Final URL: `{final}`\n- HTTP status: `{status}`\n"
        f"- Bytes stored: `{len(body)}`{' (truncated)' if truncated else ''}\n- SHA256: `{digest}`\n"
        + (f"- Title: {title}\n" if title else ""), encoding="utf-8")
    return _finish(out, {"schema": 1, "kind": "url", "target": url, "captured_at": now(), "final_url": final,
                         "http_status": status, "truncated": truncated, "policy": {"executes_remote_code": False}})


def _git(*args: str, cwd: Path | None = None, timeout=120):
    return subprocess.run(["git", *args], cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False)


def capture_repo(url: str, root: Path, label: str | None = None) -> Path:
    p = _public_url(url)
    out = _new(root, label or Path(p.path.rstrip("/")).name.removesuffix(".git") or "repo")
    with tempfile.TemporaryDirectory(prefix="only-") as td:
        repo = Path(td) / "repo"
        cp = _git("-c", "http.followRedirects=false", "clone", "--depth", "1", "--no-recurse-submodules", url, str(repo))
        if cp.returncode:
            shutil.rmtree(out, ignore_errors=True); raise OnlyError(f"git clone failed: {cp.stderr.strip()[:500]}")
        head = _git("rev-parse", "HEAD", cwd=repo).stdout.strip()
        branch = _git("branch", "--show-current", cwd=repo).stdout.strip()
        files, exts, manifests, markers = [], Counter(), [], []
        known = {"pyproject.toml","requirements.txt","package.json","package-lock.json","pnpm-lock.yaml","yarn.lock","cargo.toml","go.mod","pom.xml","dockerfile","compose.yml","docker-compose.yml"}
        for path in sorted(x for x in repo.rglob("*") if x.is_file() and ".git" not in x.parts):
            if len(files) >= MAX_FILES: break
            rel = str(path.relative_to(repo)).replace(os.sep, "/"); size = path.stat().st_size
            files.append({"path": rel, "bytes": size, "sha256": sha(path)}); exts[path.suffix.lower() or "[no-ext]"] += 1
            if path.name.lower() in known: manifests.append(rel)
            if size <= 2 * 1024 * 1024:
                try:
                    for n, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                        if re.search(r"\b(TODO|FIXME|HACK|XXX)\b", line, re.I):
                            markers.append({"path": rel, "line": n, "text": line.strip()[:300]})
                            if len(markers) >= 500: break
                except OSError: pass
        facts = {"head": head, "branch": branch, "files": len(files), "extensions": dict(exts.most_common()),
                 "dependency_manifests": manifests, "markers": markers, "executed_repository_code": False, "submodules_initialized": False}
        _json(out / "repo_facts.json", facts); _json(out / "files.json", files)
    (out / "REPORT.md").write_text(
        f"# Only repository capture\n\n- Repository: `{url}`\n- HEAD: `{head}`\n- Branch: `{branch or '(detached)'}`\n"
        f"- Files inventoried: `{len(files)}`\n- Dependency/build manifests: `{len(manifests)}`\n- Markers: `{len(markers)}`\n"
        "- Repository code executed: `no`\n- Submodules initialized: `no`\n", encoding="utf-8")
    return _finish(out, {"schema": 1, "kind": "repo", "target": url, "captured_at": now(), "head": head,
                         "policy": {"executes_repository_code": False, "initializes_submodules": False}})


def capture_file(path: Path, root: Path, label: str | None = None) -> Path:
    if not path.is_file(): raise OnlyError(f"not a file: {path}")
    out = _new(root, label or path.name); dst = out / "artifact.bin"; shutil.copy2(path, dst)
    (out / "REPORT.md").write_text(f"# Only file capture\n\n- Source: `{path.name}`\n- Bytes: `{dst.stat().st_size}`\n- SHA256: `{sha(dst)}`\n", encoding="utf-8")
    return _finish(out, {"schema": 1, "kind": "file", "target": path.name, "captured_at": now()})


def verify_capsule(out: Path) -> tuple[bool, list[str]]:
    try: manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e: return False, [f"invalid manifest: {e}"]
    declared = {x["path"]: x for x in manifest.get("evidence", [])}; problems = []
    for rel, item in declared.items():
        p = out / rel
        if not p.is_file(): problems.append(f"missing: {rel}"); continue
        if p.stat().st_size != item.get("bytes"): problems.append(f"size mismatch: {rel}")
        if sha(p) != item.get("sha256"): problems.append(f"sha256 mismatch: {rel}")
    actual = {str(p.relative_to(out)).replace(os.sep, "/") for p in out.rglob("*") if p.is_file() and p.name != "manifest.json"}
    problems += [f"undeclared file: {x}" for x in sorted(actual - set(declared))]
    return not problems, problems


def diff_capsules(left: Path, right: Path) -> dict[str, Any]:
    def load(p): return json.loads((p / "manifest.json").read_text(encoding="utf-8"))
    a, b = load(left), load(right); ae = {x["path"]: x for x in a["evidence"]}; be = {x["path"]: x for x in b["evidence"]}; changes = []
    for path in sorted(set(ae) | set(be)):
        if path not in ae: changes.append({"path": path, "change": "added"})
        elif path not in be: changes.append({"path": path, "change": "removed"})
        elif ae[path]["sha256"] != be[path]["sha256"]: changes.append({"path": path, "change": "modified"})
    return {"left": {"kind": a.get("kind"), "target": a.get("target")}, "right": {"kind": b.get("kind"), "target": b.get("target")}, "changes": changes}
