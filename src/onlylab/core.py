from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import urllib.parse
from collections import Counter
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from typing import Any

MAX_BODY = 10 * 1024 * 1024
MAX_FILES = 20_000
MAX_MARKERS = 500
MAX_REDIRECTS = 5
MAX_HTML_LINKS = 10_000
MAX_HTML_SCRIPTS = 2_000
MAX_HTML_META = 1_000
USER_AGENT = "Only/0.2 (+https://github.com/davidmariscalf/Only)"


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


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._").lower()[:80] or "capture"


def _json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def _safe_display(value: str) -> str:
    return value.encode("utf-8", errors="backslashreplace").decode("utf-8")


def _port_for(p: urllib.parse.ParseResult) -> int:
    try:
        return p.port or (443 if p.scheme == "https" else 80)
    except ValueError as exc:
        raise OnlyError("invalid target port") from exc


def _resolved_public(host: str, port: int) -> list[tuple[int, int, int, tuple[Any, ...]]]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise OnlyError(f"cannot resolve {host}") from exc

    unique: list[tuple[int, int, int, tuple[Any, ...]]] = []
    seen: set[tuple[int, int, int, tuple[Any, ...]]] = set()
    for family, socktype, proto, _canonname, sockaddr in infos:
        raw = str(sockaddr[0]).split("%", 1)[0]
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise OnlyError(f"invalid resolved address for {host}: {raw}") from exc
        if not address.is_global:
            raise OnlyError(f"refusing non-public destination: {host} -> {raw}")
        item = (family, socktype, proto, sockaddr)
        if item not in seen:
            seen.add(item)
            unique.append(item)

    if not unique:
        raise OnlyError(f"cannot resolve {host}")
    return unique


def _public_url(url: str) -> urllib.parse.ParseResult:
    p = urllib.parse.urlparse(url)
    if p.scheme not in {"http", "https"} or not p.hostname:
        raise OnlyError("target must be a public http(s) URL")
    if p.username is not None or p.password is not None:
        raise OnlyError("credentials in target URLs are not allowed")
    port = _port_for(p)
    _resolved_public(p.hostname, port)
    return p


def _ip_text(sockaddr: tuple[Any, ...]) -> str:
    return str(sockaddr[0]).split("%", 1)[0]


def _open_pinned_socket(
    info: tuple[int, int, int, tuple[Any, ...]], timeout: float
) -> socket.socket:
    family, socktype, proto, sockaddr = info
    sock = socket.socket(family, socktype, proto)
    try:
        sock.settimeout(timeout)
        sock.connect(sockaddr)
        peer = str(sock.getpeername()[0]).split("%", 1)[0]
        if not ipaddress.ip_address(peer).is_global:
            raise OnlyError(f"refusing non-public connected peer: {peer}")
        return sock
    except Exception:
        sock.close()
        raise


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, info: tuple[int, int, int, tuple[Any, ...]], timeout: float):
        super().__init__(host, port=port, timeout=timeout)
        self._only_info = info

    def connect(self) -> None:
        self.sock = _open_pinned_socket(self._only_info, float(self.timeout or 20))


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, info: tuple[int, int, int, tuple[Any, ...]], timeout: float):
        context = ssl.create_default_context()
        try:
            context.set_alpn_protocols(["http/1.1"])
        except NotImplementedError:
            pass
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._only_info = info

    def connect(self) -> None:
        raw = _open_pinned_socket(self._only_info, float(self.timeout or 20))
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def _request_target(p: urllib.parse.ParseResult) -> str:
    path = p.path or "/"
    if p.params:
        path += ";" + p.params
    if p.query:
        path += "?" + p.query
    return path


def _host_header(p: urllib.parse.ParseResult, port: int) -> str:
    assert p.hostname
    host = p.hostname.encode("idna").decode("ascii")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    default = (p.scheme == "https" and port == 443) or (p.scheme == "http" and port == 80)
    return host if default else f"{host}:{port}"


def _fetch_once(url: str, timeout: float = 20) -> dict[str, Any]:
    p = _public_url(url)
    assert p.hostname
    port = _port_for(p)
    infos = _resolved_public(p.hostname, port)
    errors: list[str] = []

    for info in infos:
        conn: http.client.HTTPConnection
        try:
            if p.scheme == "https":
                conn = _PinnedHTTPSConnection(p.hostname, port, info, timeout)
            else:
                conn = _PinnedHTTPConnection(p.hostname, port, info, timeout)

            conn.request(
                "GET",
                _request_target(p),
                headers={
                    "Host": _host_header(p, port),
                    "User-Agent": USER_AGENT,
                    "Accept": "*/*",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                },
            )
            response = conn.getresponse()
            raw = response.read(MAX_BODY + 1)
            pairs = [(str(k), str(v)) for k, v in response.getheaders()]
            by_name: dict[str, list[str]] = {}
            for key, value in pairs:
                by_name.setdefault(key.lower(), []).append(value)

            peer = None
            tls: dict[str, Any] | None = None
            if conn.sock is not None:
                peer = str(conn.sock.getpeername()[0]).split("%", 1)[0]
                if isinstance(conn.sock, ssl.SSLSocket):
                    cert = conn.sock.getpeercert(binary_form=True)
                    cipher = conn.sock.cipher()
                    tls = {
                        "protocol": conn.sock.version(),
                        "cipher": cipher[0] if cipher else None,
                        "certificate_sha256": sha_bytes(cert) if cert else None,
                    }

            return {
                "url": url,
                "status": response.status,
                "reason": response.reason,
                "body": raw,
                "header_pairs": pairs,
                "headers": by_name,
                "resolved_ips": sorted({_ip_text(x[3]) for x in infos}),
                "peer_ip": peer,
                "tls": tls,
            }
        except Exception as exc:
            errors.append(f"{_ip_text(info[3])}: {type(exc).__name__}: {exc}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    raise OnlyError(f"fetch failed for {p.hostname}: {'; '.join(errors[:3])}")


def _fetch_following_redirects(url: str) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    current = url
    hops: list[dict[str, Any]] = []
    for redirect_count in range(MAX_REDIRECTS + 1):
        result = _fetch_once(current)
        location = (result["headers"].get("location") or [None])[0]
        hops.append(
            {
                "url": current,
                "status": result["status"],
                "resolved_ips": result["resolved_ips"],
                "peer_ip": result["peer_ip"],
                "tls": result["tls"],
                "location": location,
            }
        )
        if result["status"] not in {301, 302, 303, 307, 308} or not location:
            return result, hops, current
        if redirect_count >= MAX_REDIRECTS:
            raise OnlyError(f"too many redirects (>{MAX_REDIRECTS})")
        current = urllib.parse.urljoin(current, location)
        _public_url(current)
    raise OnlyError("redirect handling failed")


class Facts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.title_bits: list[str] = []
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms = 0
        self.meta: dict[str, str] = {}
        self.links_truncated = False
        self.scripts_truncated = False
        self.meta_truncated = False

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "title":
            self.in_title = True
        elif tag == "a" and a.get("href"):
            if len(self.links) < MAX_HTML_LINKS:
                self.links.append(a["href"])
            else:
                self.links_truncated = True
        elif tag == "script" and a.get("src"):
            if len(self.scripts) < MAX_HTML_SCRIPTS:
                self.scripts.append(a["src"])
            else:
                self.scripts_truncated = True
        elif tag == "form":
            self.forms += 1
        elif tag == "meta":
            k = a.get("name") or a.get("property")
            if k and a.get("content"):
                if len(self.meta) < MAX_HTML_META or k.lower() in self.meta:
                    self.meta[k.lower()] = a["content"]
                else:
                    self.meta_truncated = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title and sum(map(len, self.title_bits)) < 16_384:
            self.title_bits.append(data)

    @property
    def title(self):
        return " ".join("".join(self.title_bits).split())[:4096]


def _new(root: Path, label: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = root / f"{stamp}-{slug(label)}"
    for attempt in range(1_000):
        out = base if attempt == 0 else Path(f"{base}-{attempt + 1}")
        try:
            out.mkdir()
            return out
        except FileExistsError:
            continue
    raise OnlyError("could not allocate a unique capture directory")


def _finish(out: Path, manifest: dict[str, Any]) -> Path:
    evidence = []
    for p in sorted(out.rglob("*")):
        if p.name == "manifest.json":
            continue
        if p.is_symlink():
            raise OnlyError(f"capsule unexpectedly contains a symlink: {p.relative_to(out)}")
        if p.is_file():
            evidence.append(
                {
                    "path": str(p.relative_to(out)).replace(os.sep, "/"),
                    "bytes": p.stat().st_size,
                    "sha256": sha(p),
                }
            )
    manifest["evidence"] = evidence
    _json(out / "manifest.json", manifest)
    return out


def capsule_digest(out: Path) -> str:
    manifest = out / "manifest.json"
    if not manifest.is_file() or manifest.is_symlink():
        raise OnlyError(f"missing regular manifest: {manifest}")
    return sha(manifest)


def capture_url(url: str, root: Path, label: str | None = None) -> Path:
    p = _public_url(url)
    out = _new(root, label or p.hostname or "url")
    try:
        result, hops, final = _fetch_following_redirects(url)
        raw = result["body"]
        truncated = len(raw) > MAX_BODY
        body = raw[:MAX_BODY]
        (out / "response.body").write_bytes(body)
        _json(out / "headers.json", {"pairs": result["header_pairs"], "by_name": result["headers"]})
        _json(out / "network.json", {"hops": hops})

        ctype = (result["headers"].get("content-type") or [""])[0]
        title = ""
        if "html" in ctype.lower() or body.lstrip().lower().startswith((b"<!doctype html", b"<html")):
            text = body.decode("utf-8", errors="replace")
            parser = Facts()
            parser.feed(text)
            title = parser.title
            _json(
                out / "html_facts.json",
                {
                    "title": title,
                    "meta": parser.meta,
                    "forms": parser.forms,
                    "links": sorted({urllib.parse.urljoin(final, x) for x in parser.links}),
                    "scripts": sorted({urllib.parse.urljoin(final, x) for x in parser.scripts}),
                    "truncated": {
                        "links": parser.links_truncated,
                        "scripts": parser.scripts_truncated,
                        "meta": parser.meta_truncated,
                    },
                },
            )

        digest = sha_bytes(body)
        (out / "REPORT.md").write_text(
            f"# Only URL capture\n\n- Requested: `{url}`\n- Final URL: `{final}`\n"
            f"- HTTP status: `{result['status']}`\n"
            f"- Bytes stored: `{len(body)}`{' (truncated)' if truncated else ''}\n"
            f"- SHA256: `{digest}`\n"
            f"- Redirect hops: `{max(0, len(hops) - 1)}`\n"
            + (f"- Title: {title}\n" if title else ""),
            encoding="utf-8",
        )
        return _finish(
            out,
            {
                "schema": 2,
                "kind": "url",
                "target": url,
                "captured_at": now(),
                "final_url": final,
                "http_status": result["status"],
                "truncated": truncated,
                "policy": {
                    "executes_remote_code": False,
                    "requires_public_destination": True,
                    "dns_pinned_per_hop": True,
                    "max_redirects": MAX_REDIRECTS,
                },
            },
        )
    except Exception:
        shutil.rmtree(out, ignore_errors=True)
        raise


def _git(*args: str, cwd: Path | None = None, timeout=120, text=True):
    env = os.environ.copy()
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        text=text,
        capture_output=True,
        timeout=timeout,
        check=False,
        env=env,
    )


def _git_resolve_rule(p: urllib.parse.ParseResult) -> tuple[str | None, list[str]]:
    assert p.hostname
    port = _port_for(p)
    infos = _resolved_public(p.hostname, port)
    addresses = sorted({_ip_text(x[3]) for x in infos})
    try:
        ipaddress.ip_address(p.hostname.split("%", 1)[0])
        return None, addresses
    except ValueError:
        pass
    formatted = [f"[{x}]" if ":" in x else x for x in addresses]
    return f"{p.hostname}:{port}:{','.join(formatted)}", addresses


def _parse_ls_files_stage(raw: bytes) -> list[tuple[str, str, str]]:
    result: list[tuple[str, str, str]] = []
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        try:
            meta, path_raw = entry.split(b"\t", 1)
            mode_raw, oid_raw, _stage = meta.split(b" ", 2)
        except ValueError as exc:
            raise OnlyError("unexpected git ls-files output") from exc
        result.append((mode_raw.decode("ascii"), oid_raw.decode("ascii"), os.fsdecode(path_raw)))
    return result


def capture_repo(url: str, root: Path, label: str | None = None) -> Path:
    p = _public_url(url)
    out = _new(root, label or Path(p.path.rstrip("/")).name.removesuffix(".git") or "repo")
    try:
        resolve_rule, resolved_ips = _git_resolve_rule(p)
        with tempfile.TemporaryDirectory(prefix="only-") as td:
            repo = Path(td) / "repo"
            git_args = [
                "-c",
                "http.followRedirects=false",
                "-c",
                "credential.helper=",
                "-c",
                "http.proxy=",
            ]
            if resolve_rule:
                git_args += ["-c", f"http.curloptResolve={resolve_rule}"]
            git_args += ["clone", "--depth", "1", "--no-recurse-submodules", url, str(repo)]
            cp = _git(*git_args)
            if cp.returncode:
                stderr = cp.stderr.strip() if isinstance(cp.stderr, str) else cp.stderr.decode("utf-8", "replace").strip()
                raise OnlyError(f"git clone failed: {stderr[:500]}")

            head = _git("rev-parse", "HEAD", cwd=repo).stdout.strip()
            branch = _git("branch", "--show-current", cwd=repo).stdout.strip()
            listing = _git("ls-files", "--stage", "-z", cwd=repo, text=False)
            if listing.returncode:
                stderr = listing.stderr.decode("utf-8", "replace").strip()
                raise OnlyError(f"git ls-files failed: {stderr[:500]}")
            tracked = _parse_ls_files_stage(listing.stdout)
            inventory_truncated = len(tracked) > MAX_FILES
            selected = tracked[:MAX_FILES]

            files: list[dict[str, Any]] = []
            exts: Counter[str] = Counter()
            manifests: list[str] = []
            markers: list[dict[str, Any]] = []
            markers_truncated = False
            known = {
                "pyproject.toml",
                "requirements.txt",
                "package.json",
                "package-lock.json",
                "pnpm-lock.yaml",
                "yarn.lock",
                "cargo.toml",
                "go.mod",
                "pom.xml",
                "dockerfile",
                "compose.yml",
                "docker-compose.yml",
            }

            for mode, oid, rel_actual in selected:
                path = repo / rel_actual
                rel = _safe_display(rel_actual).replace(os.sep, "/")
                base: dict[str, Any] = {"path": rel, "git_mode": mode, "git_oid": oid}

                if mode == "160000":
                    base.update({"type": "gitlink", "bytes": None, "sha256": None})
                    files.append(base)
                    continue

                if path.is_symlink() or mode == "120000":
                    target = os.readlink(path)
                    target_bytes = os.fsencode(target)
                    base.update(
                        {
                            "type": "symlink",
                            "bytes": len(target_bytes),
                            "sha256": sha_bytes(target_bytes),
                            "symlink_target": _safe_display(target),
                        }
                    )
                    files.append(base)
                    continue

                if not path.is_file():
                    base.update({"type": "missing_or_special", "bytes": None, "sha256": None})
                    files.append(base)
                    continue

                size = path.stat().st_size
                base.update({"type": "file", "bytes": size, "sha256": sha(path)})
                files.append(base)
                exts[path.suffix.lower() or "[no-ext]"] += 1
                if path.name.lower() in known:
                    manifests.append(rel)

                if size <= 2 * 1024 * 1024 and not markers_truncated:
                    try:
                        for n, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                            if re.search(r"\b(TODO|FIXME|HACK|XXX)\b", line, re.I):
                                markers.append({"path": rel, "line": n, "text": line.strip()[:300]})
                                if len(markers) >= MAX_MARKERS:
                                    markers_truncated = True
                                    break
                    except OSError:
                        pass

            facts = {
                "head": head,
                "branch": branch,
                "tracked_files": len(tracked),
                "files_inventoried": len(files),
                "inventory_truncated": inventory_truncated,
                "extensions": dict(exts.most_common()),
                "dependency_manifests": manifests,
                "markers": markers,
                "markers_truncated": markers_truncated,
                "resolved_ips": resolved_ips,
                "dns_pinned_for_clone": bool(resolve_rule) or bool(resolved_ips),
                "executed_repository_code": False,
                "submodules_initialized": False,
                "symlinks_followed": False,
            }
            _json(out / "repo_facts.json", facts)
            _json(out / "files.json", files)

        (out / "REPORT.md").write_text(
            f"# Only repository capture\n\n- Repository: `{url}`\n- HEAD: `{head}`\n"
            f"- Branch: `{branch or '(detached)'}`\n- Tracked files: `{len(tracked)}`\n"
            f"- Files inventoried: `{len(files)}`{' (truncated)' if inventory_truncated else ''}\n"
            f"- Dependency/build manifests: `{len(manifests)}`\n"
            f"- Markers: `{len(markers)}`{' (truncated)' if markers_truncated else ''}\n"
            "- Repository code executed: `no`\n- Submodules initialized: `no`\n- Symlinks followed: `no`\n",
            encoding="utf-8",
        )
        return _finish(
            out,
            {
                "schema": 2,
                "kind": "repo",
                "target": url,
                "captured_at": now(),
                "head": head,
                "inventory_truncated": inventory_truncated,
                "policy": {
                    "executes_repository_code": False,
                    "initializes_submodules": False,
                    "follows_repository_symlinks": False,
                    "requires_public_destination": True,
                    "dns_pinned_for_clone": True,
                    "isolates_git_config": True,
                },
            },
        )
    except Exception:
        shutil.rmtree(out, ignore_errors=True)
        raise


def capture_file(path: Path, root: Path, label: str | None = None) -> Path:
    if not path.is_file() or path.is_symlink():
        raise OnlyError(f"not a regular file: {path}")
    out = _new(root, label or path.name)
    try:
        dst = out / "artifact.bin"
        shutil.copyfile(path, dst)
        (out / "REPORT.md").write_text(
            f"# Only file capture\n\n- Source: `{path.name}`\n- Bytes: `{dst.stat().st_size}`\n"
            f"- SHA256: `{sha(dst)}`\n",
            encoding="utf-8",
        )
        return _finish(out, {"schema": 2, "kind": "file", "target": path.name, "captured_at": now()})
    except Exception:
        shutil.rmtree(out, ignore_errors=True)
        raise


def _safe_manifest_path(out: Path, rel: Any) -> tuple[Path | None, str | None]:
    if not isinstance(rel, str) or not rel or "\\" in rel:
        return None, "evidence path must be a non-empty portable relative path"
    posix = PurePosixPath(rel)
    if posix.is_absolute() or any(part in {"", ".", ".."} for part in posix.parts):
        return None, f"unsafe evidence path: {rel}"
    candidate = out.joinpath(*posix.parts)
    try:
        root_real = out.resolve()
        candidate_real = candidate.resolve(strict=False)
        candidate_real.relative_to(root_real)
    except (OSError, ValueError):
        return None, f"evidence path escapes capsule: {rel}"
    return candidate, None


def _load_manifest(out: Path) -> dict[str, Any]:
    manifest_path = out / "manifest.json"
    if manifest_path.is_symlink():
        raise OnlyError("manifest.json must not be a symlink")
    try:
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OnlyError(f"invalid manifest: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("evidence"), list):
        raise OnlyError("invalid manifest structure")
    return value


def verify_capsule(out: Path) -> tuple[bool, list[str]]:
    try:
        manifest = _load_manifest(out)
    except OnlyError as exc:
        return False, [str(exc)]

    declared: dict[str, dict[str, Any]] = {}
    problems: list[str] = []
    for item in manifest.get("evidence", []):
        if not isinstance(item, dict):
            problems.append("invalid evidence entry")
            continue
        rel = item.get("path")
        candidate, error = _safe_manifest_path(out, rel)
        if error:
            problems.append(error)
            continue
        assert isinstance(rel, str) and candidate is not None
        if rel in declared:
            problems.append(f"duplicate evidence path: {rel}")
            continue
        declared[rel] = item
        if candidate.is_symlink():
            problems.append(f"symlink evidence is not allowed: {rel}")
            continue
        if not candidate.is_file():
            problems.append(f"missing: {rel}")
            continue
        expected_bytes = item.get("bytes")
        expected_sha = item.get("sha256")
        if not isinstance(expected_bytes, int) or expected_bytes < 0:
            problems.append(f"invalid byte length: {rel}")
        elif candidate.stat().st_size != expected_bytes:
            problems.append(f"size mismatch: {rel}")
        if not isinstance(expected_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
            problems.append(f"invalid sha256: {rel}")
        elif sha(candidate) != expected_sha:
            problems.append(f"sha256 mismatch: {rel}")

    actual: set[str] = set()
    try:
        for p in out.rglob("*"):
            if p.name == "manifest.json":
                continue
            if p.is_symlink() or p.is_file():
                actual.add(str(p.relative_to(out)).replace(os.sep, "/"))
    except OSError as exc:
        problems.append(f"cannot enumerate capsule: {exc}")

    problems += [f"undeclared file: {x}" for x in sorted(actual - set(declared))]
    return not problems, problems


def diff_capsules(left: Path, right: Path) -> dict[str, Any]:
    left_ok, left_problems = verify_capsule(left)
    right_ok, right_problems = verify_capsule(right)
    if not left_ok:
        raise OnlyError("left capsule failed verification: " + "; ".join(left_problems[:5]))
    if not right_ok:
        raise OnlyError("right capsule failed verification: " + "; ".join(right_problems[:5]))

    a = _load_manifest(left)
    b = _load_manifest(right)
    ae = {x["path"]: x for x in a["evidence"]}
    be = {x["path"]: x for x in b["evidence"]}
    changes = []
    for path in sorted(set(ae) | set(be)):
        if path not in ae:
            changes.append({"path": path, "change": "added"})
        elif path not in be:
            changes.append({"path": path, "change": "removed"})
        elif ae[path]["sha256"] != be[path]["sha256"]:
            changes.append({"path": path, "change": "modified"})
    return {
        "left": {"kind": a.get("kind"), "target": a.get("target"), "manifest_sha256": capsule_digest(left)},
        "right": {"kind": b.get("kind"), "target": b.get("target"), "manifest_sha256": capsule_digest(right)},
        "changes": changes,
    }
