"""Public repository allowlist, built from the FILESYSTEM (no Git command is run).

The owner will create a clean repository from exactly these files. Nothing is published unless a rule below includes it:

  * explicit top-level files and directories (source, migrations, lockfiles, tests, deployment templates, public docs);
  * the web app's source is limited to what the routed pages actually import (an import-graph closure from
    src/app/** and src/proxy.ts): unrouted legacy UI extracted from the original product is not published;
  * a web unit test is published only when every source file it loads is published (tests of legacy UI are not);
  * hard exclusions win: environment files, keys, databases, dumps, logs, caches, build output, dependencies,
    virtualenvs, local state, legacy reference code, provenance, engineering documents, internal reports, info.md.

Every published file is then scanned for content that must not be public: personal e-mail addresses (only
*.invalid / example.* / test domains are allowed), public IPv4 addresses (RFC 1918/5737/loopback allowed), legacy
hosting hostnames (railway.app, vercel.app) and private key material.

  python scripts/release/publication.py                 write release/PUBLIC_ALLOWLIST.txt and release/PUBLIC_MANIFEST.tsv
  python scripts/release/publication.py --check         exit 1 if the manifest is stale or the content scan finds anything
  python scripts/release/publication.py --stage DIR     copy exactly the allowlisted files into an EMPTY directory DIR
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "release"
ALLOWLIST, MANIFEST = OUT / "PUBLIC_ALLOWLIST.txt", OUT / "PUBLIC_MANIFEST.tsv"

INCLUDE_FILES = ["README.md", ".gitignore", ".gitattributes", ".dockerignore", ".gitleaks.toml", "LICENSE", "NOTICE"]
INCLUDE_DIRS = [".github", "apps/api", "packages/contracts", "packages/db", "services/edge", "services/vms-worker", "deploy",
                "scripts/contracts", "scripts/dev", "scripts/e2e", "scripts/release", "docs/public", "release"]
WEB_ROOT_FILES = ["package.json", "package-lock.json", "next.config.ts", "tsconfig.json", "eslint.config.mjs",
                  "postcss.config.mjs"]
# Hard exclusions (path segments, suffixes, exact paths). They apply inside included directories too.
EXCLUDE_SEGMENTS = {"node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", ".next", ".run", ".mypy_cache", ".ruff_cache",
                    "dist", "build", "coverage", ".turbo"}
EXCLUDE_SUFFIXES = (".pyc", ".pyo", ".log", ".sqlite", ".sqlite3", ".db", ".dump", ".nvsb", ".pem", ".key", ".p12", ".pfx", ".crt",
                    ".tsbuildinfo", ".egg-info")
EXCLUDE_NAMES = {".env", "info.md", ".DS_Store", "Thumbs.db", "next.config.compiled.js"}
EXCLUDE_PATHS = {"scripts/dev/demo", "scripts/dev/seed_demo.py", "services/vms-worker/worker.env.example", "deploy/dev/.env"}
EXCLUDED_REASONS = [  # reported, for the owner's review (nothing here is published)
    ("reference/", "legacy NovrSOC and NCC reference code"), ("provenance/", "private provenance records and snapshots"),
    ("docs/", "engineering documents, internal reports, historical evidence (only docs/public is published)"),
    ("apps/web/src/", "unrouted legacy UI extracted from the original product (not imported by any routed page)"),
    ("apps/web/scripts/", "tests and checks of unpublished legacy UI"), ("apps/web/docs", "engineering notes"),
    ("apps/web/EXTRACTION_STATUS.md", "engineering notes"), ("packages/domain", "planning README only"),
    ("packages/config", "planning README only"), ("services/", "planning README stubs; the legacy Railway worker configuration"),
    ("scripts/git", "local repository bootstrap tooling"), ("scripts/provenance", "provenance tooling"),
    ("scripts/dev/demo", "synthetic local demonstration data (local preview only)"), ("info.md", "the owner's private notes"),
]

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
HOSTS = re.compile(r"[a-z0-9.-]+\.(up\.railway\.app|railway\.app|vercel\.app)\b", re.I)
# Links into material that is never published (internal docs, the legacy reference tree) and the hosting provider's name.
DOCREF = re.compile(r"(?<![\w/.-])(?:\.\./)*(docs/(?!public/)[A-Za-z0-9_.-]+|reference/[A-Za-z0-9_-]+|provenance/)")
PROVIDER = re.compile(r"contabo", re.I)
# Ignore files, the gitleaks allowlist and the preflight rules name excluded paths on purpose.
PATH_RULE_FILES = {".gitignore", ".dockerignore", ".gitleaks.toml", "scripts/release/preflight.py"}
PRIVKEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
ALLOWED_EMAIL_DOMAINS = re.compile(r"(\.invalid|\.test|\.example|\.localhost|example\.(com|org|net))$", re.I)
ALLOWED_EMAILS = {"noreply@anthropic.com", "git@github.com", "noreply@github.com"}
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "0.0.0.0/8", "255.255.255.255/32",
                                                "224.0.0.0/4", "100.64.0.0/10")]
TEXT_SUFFIXES = {".py", ".ts", ".tsx", ".mjs", ".js", ".json", ".md", ".yaml", ".yml", ".toml", ".txt", ".example", ".service", ".timer",
                 ".conf", ".sh", ".ps1", ".css", ".ini", ".xml", ".cfg", ".tsv", ".html", ".mako", ""}
# Reviewed false positives: version strings and OIDs that look like addresses, fixture data that is documentation-only.
IP_LIKE_OK = re.compile(r"^(1\.3\.6\.1|2\.5\.4|1\.2\.840)")
# Reviewed exceptions (file, finding): unit-test inputs that must be globally routable (the worker's routing checks use
# ipaddress.is_global, which documentation ranges are not). They are never contacted. A synthetic key for the redaction test.
REVIEWED = {("services/vms-worker/test_worker.py", "public IPv4 address 8.8.8.8"),
            ("services/vms-worker/test_worker.py", "public IPv4 address 196.1.2.3"),
            ("services/vms-worker/test_worker.py", "public IPv4 address 196.1.2.4"),
            ("apps/api/tests/test_redact.py", "private key material")}


def _excluded(rel: str) -> bool:
    parts = rel.split("/")
    if any(p in EXCLUDE_SEGMENTS or p.endswith(".egg-info") for p in parts):
        return True
    if parts[-1] in EXCLUDE_NAMES or (parts[-1].startswith(".env") and not parts[-1].endswith(".example")):
        return True
    if rel.endswith(EXCLUDE_SUFFIXES):
        return True
    return any(rel == x or rel.startswith(x + "/") for x in EXCLUDE_PATHS)


def _walk(base: str) -> list[str]:
    root = ROOT / base
    if root.is_file():
        return [base]
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_SEGMENTS and not d.endswith(".egg-info")]
        for f in filenames:
            out.append(Path(dirpath, f).relative_to(ROOT).as_posix())
    return out


# ---------------------------------------------------------------- web: import closure of the routed app
IMPORT = re.compile(r"""(?:import|export)\s[^'"]*?from\s+['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]\s*\)|import\s+['"]([^'"]+)['"]""")
WEB = ROOT / "apps" / "web"


def _resolve(spec: str, from_file: Path) -> Path | None:
    if spec.startswith("@/"):
        base = WEB / "src" / spec[2:]
    elif spec.startswith("."):
        base = (from_file.parent / spec).resolve()
    else:
        return None
    for cand in (base, *[base.with_name(base.name + e) for e in (".ts", ".tsx", ".js", ".mjs", ".css")],
                 *[base / f"index{e}" for e in (".ts", ".tsx", ".js")]):
        if cand.is_file():
            return cand
    return None


def web_closure() -> set[str]:
    entries = [p for p in (WEB / "src" / "app").rglob("*") if p.is_file()] + [WEB / "src" / "proxy.ts"]
    seen: set[Path] = set()
    stack = [p for p in entries if p.exists()]
    while stack:
        f = stack.pop()
        if f in seen:
            continue
        seen.add(f)
        if f.suffix not in (".ts", ".tsx", ".js", ".mjs"):
            continue
        for m in IMPORT.finditer(f.read_text(encoding="utf-8", errors="replace")):
            dep = _resolve(next(g for g in m.groups() if g), f)
            if dep is not None and dep not in seen:
                stack.append(dep)
    return {p.relative_to(ROOT).as_posix() for p in seen}


# Web scripts published with the app (reviewed): each checks or tests only published code. The others test unrouted
# legacy UI (vms-*, cnii-intake, severity, playbook-logic), the legacy sidebar (check-nav-routes), legacy pages
# (browser-check) or carry an allowlist of legacy files (design-tokens), so they would not run in the public tree.
WEB_SCRIPTS = """
    foundation.test.mjs  contrast-tokens.test.mjs  check-v2-nav.mjs  check-api-types.mjs  e2e-foundation.mjs
    browser/cdp.mjs  browser/audit.mjs  lib/ts-graph.mjs
""".split()


def web_scripts(closure: set[str]) -> list[str]:
    out = []
    for name in WEB_SCRIPTS:
        rel = f"apps/web/scripts/{name}"
        text = (ROOT / rel).read_text(encoding="utf-8")
        missing = [m for m in re.findall(r"""['"](src/[^'"]+)['"]""", text) if f"apps/web/{m}" not in closure]
        if missing:
            raise SystemExit(f"{rel} loads unpublished source {missing}")
        out.append(rel)
    return out


def allowlist() -> list[str]:
    files: set[str] = set()
    for f in INCLUDE_FILES:
        if (ROOT / f).is_file():
            files.add(f)
    for d in INCLUDE_DIRS:
        if (ROOT / d).exists():
            files.update(_walk(d))
    for f in WEB_ROOT_FILES:
        if (WEB / f).is_file():
            files.add(f"apps/web/{f}")
    files.update(_walk("apps/web/public"))
    closure = web_closure() | {"apps/web/src/foundation/api/contracts.gen.ts", "apps/web/src/foundation/api/schema.gen.ts"}  # generated, checked
    files.update(p for p in closure if p.startswith("apps/web/src/"))
    files.update(web_scripts(closure))
    files.update({"release/PUBLIC_ALLOWLIST.txt", "release/PUBLIC_MANIFEST.tsv"})   # always listed (the manifest cannot hash itself)
    return sorted(p for p in files if not _excluded(p))


def scan(paths: list[str]) -> list[str]:
    problems = []
    for rel in paths:
        p = ROOT / rel
        if rel == "scripts/release/publication.py":   # the rules themselves (they name the reviewed exceptions)
            continue
        if not p.exists() or p.suffix not in TEXT_SUFFIXES or p.stat().st_size > 2_000_000 or rel.startswith("release/"):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        for m in EMAIL.finditer(text):
            addr = m.group(0).rstrip(".")
            dom = addr.split("@", 1)[1]
            if addr.lower() in ALLOWED_EMAILS or ALLOWED_EMAIL_DOMAINS.search(dom) or re.match(r"^\d", dom) or "{" in addr:
                continue
            problems.append(f"{rel}: e-mail address {addr}")
        for m in IPV4.finditer(text):
            s = m.group(0)
            if IP_LIKE_OK.match(s):
                continue
            try:
                ip = ipaddress.ip_address(s)
            except ValueError:
                continue
            if ip.is_private or ip.is_loopback or ip.is_unspecified or any(ip in n for n in DOC_NETS):
                continue
            line = text[max(0, m.start() - 40):m.end() + 10]
            if re.search(r"(version|v\d|==|>=|<=|\d\.\d\.\d+\.\d+-)", line, re.I) and int(s.split(".")[0]) < 30:
                continue          # a dotted version number, not an address
            problems.append(f"{rel}: public IPv4 address {s}")
        for m in HOSTS.finditer(text):
            problems.append(f"{rel}: legacy hosting hostname {m.group(0)}")
        for m in (DOCREF.finditer(text) if rel not in PATH_RULE_FILES else ()):
            problems.append(f"{rel}: link to unpublished path {m.group(1)}")
        if PROVIDER.search(text):
            problems.append(f"{rel}: hosting provider name")
        if PRIVKEY.search(text):
            problems.append(f"{rel}: private key material")
    return [p for p in problems if tuple(p.split(": ", 1)) not in REVIEWED]


def published_bytes(rel: str) -> bytes:
    """The bytes a checkout holds: Git stores text with LF endings (.gitattributes `* text=auto`), so text files are
    hashed and staged with LF, whatever the working tree on this machine uses. Binary files are taken as they are."""
    b = (ROOT / rel).read_bytes()
    if Path(rel).suffix in TEXT_SUFFIXES and b"\0" not in b:
        return b.replace(b"\r\n", b"\n")
    return b


def manifest_lines(paths: list[str]) -> list[str]:
    lines = ["path\tsha256\tbytes"]
    for rel in paths:
        if rel in ("release/PUBLIC_MANIFEST.tsv",):
            continue
        if not (ROOT / rel).exists():
            continue
        b = published_bytes(rel)
        lines.append(f"{rel}\t{hashlib.sha256(b).hexdigest()}\t{len(b)}")
    return lines


def main(argv: list[str]) -> int:
    paths = allowlist()
    if "--stage" in argv:
        dest = Path(argv[argv.index("--stage") + 1]).resolve()
        if dest.exists() and any(dest.iterdir()):
            print(f"refused: {dest} is not empty", file=sys.stderr)
            return 2
        if ROOT in dest.parents or dest == ROOT:
            print("refused: stage outside the working tree", file=sys.stderr)
            return 2
        for rel in paths:
            t = dest / rel
            t.parent.mkdir(parents=True, exist_ok=True)
            t.write_bytes(published_bytes(rel))
            shutil.copystat(ROOT / rel, t)
        print(f"staged {len(paths)} files into {dest}")
        return 0
    problems = scan(paths)
    if "--check" in argv:
        stale = not MANIFEST.exists() or MANIFEST.read_text(encoding="utf-8").splitlines() != manifest_lines(paths) \
            or not ALLOWLIST.exists() or ALLOWLIST.read_text(encoding="utf-8").splitlines() != paths
        for p in problems:
            print("CONTENT  " + p)
        if stale:
            print("STALE    the allowlist or manifest does not match the files; run scripts/release/publication.py")
        print(f"publication: {len(paths)} files allowlisted; {len(problems)} content problem(s); manifest {'stale' if stale else 'current'}")
        return 1 if problems or stale else 0
    OUT.mkdir(exist_ok=True)
    ALLOWLIST.write_text("\n".join(paths) + "\n", encoding="utf-8", newline="\n")
    MANIFEST.write_text("\n".join(manifest_lines(paths)) + "\n", encoding="utf-8", newline="\n")
    size = sum((ROOT / p).stat().st_size for p in paths)
    print(f"wrote {ALLOWLIST.relative_to(ROOT)} and {MANIFEST.relative_to(ROOT)}: {len(paths)} files, {size / 1e6:.1f} MB")
    for p in problems:
        print("CONTENT  " + p)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
