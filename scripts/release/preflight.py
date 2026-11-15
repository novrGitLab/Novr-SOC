"""Release preflight: publication and deployment safety checks. Read-only, and it runs NO Git command: the owner
creates the public repository from the allowlisted files (scripts/release/publication.py --stage).

  python scripts/release/preflight.py            # every check; exit 1 if any FAIL
  python scripts/release/preflight.py --no-docker --no-gitleaks   # CI jobs without those tools

Checks
  publication   the public allowlist is current; no forbidden file (env files, keys, databases, credentials, info.md,
                snapshots, build output) is allowlisted; no file over 2 MiB; the content scan finds no personal e-mail,
                public IP, legacy hosting hostname or private key in any published file
  secrets       gitleaks (directory mode) over a staged copy of exactly the allowlisted files
  compose       deploy/server2/compose.yaml as Docker resolves it: loopback-only ports, no privileged containers, no
                Docker socket, read-only roots, all capabilities dropped (PostgreSQL: the five it needs),
                no-new-privileges, third-party images pinned by digest, an internal database network
  templates     every published *.env.example / *.json.example carries placeholders, never a value for a secret
  dockerfiles   base images pinned by digest, a non-root USER
  dependencies  apps/api/requirements.runtime.lock matches the tested lock; no Vercel or Railway package or config
Server 1 has no compose file: it runs on the existing Python/systemd environment (deploy/server1/*.service).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RESULTS: list[tuple[str, str, str]] = []

FORBIDDEN = [
    (re.compile(r"(^|/)\.env(\.(?!example$)[^/]*)?$"), "environment file"),
    (re.compile(r"\.(pem|key|p12|pfx|sqlite|sqlite3|db|dump|nvsb)$"), "key, certificate store, database or backup"),
    (re.compile(r"(^|/)(node_modules|\.next|\.venv|__pycache__|\.pytest_cache|\.run)/"), "generated or runtime artefact"),
    (re.compile(r"^provenance/snapshots/"), "archive snapshot of another repository's uncommitted work"),
    (re.compile(r"dev-credentials\.json$|first-admin\.txt$|\.token$|\.password$"), "credential file"),
    (re.compile(r"\.tsbuildinfo$|(^|/)next-env\.d\.ts$"), "build artefact"),
    (re.compile(r"^info\.md$"), "owner's private notes (kept out of the repository)"),
]
LARGE = 2 * 1024 * 1024
SECRET_NAME = re.compile(r"(PASSWORD|SECRET|(^|_)TOKEN$|(^|_)KEY$|PRIVATE)", re.I)   # names of secrets, not e.g. MAX_TOKENS


def record(area: str, ok: bool | None, detail: str) -> None:
    RESULTS.append((area, "OK" if ok else "SKIP" if ok is None else "FAIL", detail))


def published() -> list[str]:
    f = ROOT / "release" / "PUBLIC_ALLOWLIST.txt"
    return [line for line in f.read_text(encoding="utf-8").splitlines() if line] if f.exists() else []


def check_publication() -> None:
    py = sys.executable
    r = subprocess.run([py, str(ROOT / "scripts" / "release" / "publication.py"), "--check"], cwd=ROOT, capture_output=True, text=True)
    record("publication", r.returncode == 0, (r.stdout.strip().splitlines() or ["no output"])[-1])
    files = published()
    bad = [f"{p} ({why})" for p in files for rx, why in FORBIDDEN if rx.search(p) and not p.endswith("next-env.d.ts")]
    big = [p for p in files if (ROOT / p).exists() and (ROOT / p).stat().st_size > LARGE]
    record("publication", bool(files) and not bad and not big,
           f"{len(files)} allowlisted files; " + ("; ".join(bad[:10] + [f"{p} over 2 MiB" for p in big]) or "no forbidden or large file"))


def check_secrets() -> None:
    exe = shutil.which("gitleaks") or str(ROOT / ".run" / "tools" / ("gitleaks.exe" if os.name == "nt" else "gitleaks"))
    if not Path(exe).exists():
        record("secrets", None, "gitleaks not installed here")
        return
    import tempfile
    stage = Path(tempfile.mkdtemp(prefix="novrsoc-stage-")) / "repo"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "release" / "publication.py"), "--stage", str(stage)], capture_output=True, check=True)
    shutil.copy2(ROOT / ".gitleaks.toml", stage / ".gitleaks.toml") if not (stage / ".gitleaks.toml").exists() else None
    r = subprocess.run([exe, "dir", ".", "--config", ".gitleaks.toml", "--redact", "--no-banner", "--exit-code", "1"],
                       cwd=stage, capture_output=True, text=True)
    tail = [line for line in (r.stdout + r.stderr).splitlines() if line.strip()]
    shutil.rmtree(stage.parent, ignore_errors=True)
    record("secrets", r.returncode == 0, "gitleaks dir (staged public files): " + (tail[-1] if tail else ""))


# ---------------------------------------------------------------- compose
def compose_json(path: Path, env: dict[str, str], profiles: bool) -> dict:
    cmd = ["docker", "compose", "-f", str(path)] + (["--profile", "*"] if profiles else []) + ["config", "--format", "json"]
    r = subprocess.run(cmd, cwd=path.parent, capture_output=True, text=True, env={**os.environ, **env})
    if r.returncode:
        raise RuntimeError(r.stderr.strip())
    return json.loads(r.stdout)


def check_compose() -> None:
    if not shutil.which("docker"):
        record("compose", None, "docker not installed here")
        return
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="novrsoc-preflight-"))
    (tmp / "secrets").mkdir()
    for name in ("api.env", "migrate.env", "backup.env", "secrets/pg_superuser_password", "secrets/pg_owner_password",
                 "secrets/pg_app_password"):
        (tmp / name).write_text("", encoding="utf-8")   # empty stand-ins: compose only needs the files to exist
    dummy = {"NOVRSOC_IMAGE_TAG": "preflight", "NOVRSOC_CONFIG_DIR": str(tmp), "NOVRSOC_BACKUP_DIR": str(tmp)}
    if (ROOT / "deploy" / "server1" / "compose.yaml").exists():
        record("compose", False, "server1: a compose file exists, but Server 1 runs on Python/systemd (owner decision)")
    for server in ("server2",):
        path = ROOT / "deploy" / server / "compose.yaml"
        try:
            cfg = compose_json(path, dummy, profiles=True)
            default = compose_json(path, dummy, profiles=False)
        except (RuntimeError, ValueError) as e:
            record("compose", False, f"{server}: does not resolve: {e}")
            continue
        problems = []
        for name, s in cfg["services"].items():
            image = s.get("image", "")
            if not image.startswith("novrsoc-") and "@sha256:" not in image:
                problems.append(f"{name}: third-party image not pinned by digest ({image})")
            if image.startswith("novrsoc-") and not image.endswith(":preflight"):
                problems.append(f"{name}: own image not tagged from NOVRSOC_IMAGE_TAG ({image})")
            if s.get("privileged"):
                problems.append(f"{name}: privileged")
            for v in s.get("volumes", []):
                if "docker.sock" in str(v.get("source", "")):
                    problems.append(f"{name}: mounts the Docker socket")
            for p in s.get("ports", []):
                if p.get("host_ip") not in ("127.0.0.1", "::1"):
                    problems.append(f"{name}: port {p.get('published')} published on {p.get('host_ip') or 'all interfaces'}")
            if "ALL" not in (s.get("cap_drop") or []):
                problems.append(f"{name}: capabilities not dropped")
            extra = set(s.get("cap_add") or [])
            if extra and not (name == "postgres" and extra <= {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"}):
                problems.append(f"{name}: unexpected capabilities {sorted(extra)}")
            if "no-new-privileges:true" not in (s.get("security_opt") or []):
                problems.append(f"{name}: no-new-privileges missing")
            if name != "postgres" and not s.get("read_only"):
                problems.append(f"{name}: root filesystem writable")
            if server == "server2" and s.get("network_mode") == "host":
                problems.append(f"{name}: host networking on Server 2")
            if server == "server1" and not s.get("profiles"):
                problems.append(f"{name}: starts without a gate profile")
        if server == "server1" and default.get("services"):
            problems.append("services start without a profile: " + ", ".join(default["services"]))
        if server == "server2":
            nets = cfg.get("networks", {})
            if not nets.get("db", {}).get("internal"):
                problems.append("database network is not internal")
            if cfg["services"].get("postgres", {}).get("ports"):
                problems.append("postgres publishes a port")
        record("compose", not problems, f"{server}: {len(cfg['services'])} services; " + ("; ".join(problems) or "hardening rules met"))
    shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- templates
def check_templates() -> None:
    files = [ROOT / p for p in published() if p.endswith((".env.example", ".json.example"))]
    issues = []
    for f in sorted(set(files)):
        text = f.read_text(encoding="utf-8")
        if f.suffix == ".example" and f.name.endswith(".json.example"):
            def walk(o, path=""):
                if isinstance(o, dict):
                    for k, v in o.items():
                        walk(v, f"{path}.{k}")
                elif isinstance(o, str) and SECRET_NAME.search(path.rsplit(".", 1)[-1]) and not path.endswith("_file") \
                        and o and not o.startswith(("<", "/")):
                    issues.append(f"{f.relative_to(ROOT)}: {path} has a value")
            walk(json.loads(text))
            continue
        for n, line in enumerate(text.splitlines(), 1):
            m = re.match(r"^\s*([A-Z0-9_]+)=(.*)$", line)
            if not m:
                continue
            key, val = m.group(1), m.group(2).strip()
            if key.endswith("_FILE") or not SECRET_NAME.search(key):
                pass
            elif val and not val.startswith("<"):
                issues.append(f"{f.relative_to(ROOT)}:{n} {key} has a value")
            if "://" in val and re.search(r"://[^:/@<]+:(?!<)[^@]+@", val):
                issues.append(f"{f.relative_to(ROOT)}:{n} {key} embeds a credential")
    record("templates", not issues, f"{len(set(files))} templates; " + ("; ".join(issues) or "placeholders only"))


# ---------------------------------------------------------------- dockerfiles
def check_dockerfiles() -> None:
    issues = []
    files = sorted((ROOT / "deploy" / "docker").glob("*.Dockerfile"))
    for f in files:
        text = f.read_text(encoding="utf-8")
        for m in re.finditer(r"^FROM\s+(\S+)", text, re.M):
            if "@sha256:" not in m.group(1):
                issues.append(f"{f.name}: FROM {m.group(1)} not pinned by digest")
        users = re.findall(r"^USER\s+(\S+)", text, re.M)
        if not users or users[-1].split(":")[0] in ("root", "0"):
            issues.append(f"{f.name}: no non-root USER")
    record("dockerfiles", bool(files) and not issues, f"{len(files)} Dockerfiles; " + ("; ".join(issues) or "pinned, non-root"))


# ---------------------------------------------------------------- dependencies
def check_dependencies() -> None:
    venv = ROOT / "apps" / "api" / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    py = str(venv) if venv.exists() else sys.executable
    r = subprocess.run([py, str(ROOT / "scripts" / "release" / "runtime_lock.py"), "--check"], cwd=ROOT, capture_output=True, text=True)
    record("dependencies", r.returncode == 0, (r.stdout or r.stderr).strip())
    pkg = json.loads((ROOT / "apps" / "web" / "package.json").read_text(encoding="utf-8"))
    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
    hosted = [d for d in deps if "vercel" in d.lower() or "railway" in d.lower()] + \
        [p for p in published() if p.endswith(("vercel.json", "railway.json", "railway.toml", ".vercelignore"))]
    cfg = (ROOT / "apps" / "web" / "next.config.ts").read_text(encoding="utf-8").lower()
    ok = not hosted and "vercel" not in cfg and "railway" not in cfg
    record("dependencies", ok, "no Vercel or Railway package, config or build setting" if ok else f"hosting references: {hosted}")


def main() -> int:
    check_publication()
    if "--no-gitleaks" not in sys.argv:
        check_secrets()
    if "--no-docker" not in sys.argv:
        check_compose()
    check_templates()
    check_dockerfiles()
    check_dependencies()
    width = max(len(a) for a, _, _ in RESULTS)
    for area, status, detail in RESULTS:
        print(f"{status:4}  {area:<{width}}  {detail}")
    failed = sum(1 for _, s, _ in RESULTS if s == "FAIL")
    print(f"\npreflight: {len(RESULTS) - failed}/{len(RESULTS)} checks without failure" + (f", {failed} FAILED" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
