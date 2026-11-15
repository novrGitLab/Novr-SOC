"""Architecture guard: Next.js -> FastAPI -> internal services. The web app never addresses Wazuh, the
indexer, Ollama, Greenbone or PostgreSQL directly, and only /api/v1 is proxied to the API."""
import re
from pathlib import Path

WEB = Path(__file__).resolve().parents[2] / "web"
FORBIDDEN = [
    (re.compile(r"https?://[^\s'\"`]*:(55000|9200|11434|9390|5432|55432)\b"), "internal service port in a URL"),
    (re.compile(r"postgres(ql)?(\+\w+)?://", re.I), "database URL"),
    (re.compile(r"/run/gvmd|gvmd\.sock", re.I), "Greenbone socket"),
    (re.compile(r"NEXT_PUBLIC_[A-Z_]*(WAZUH|INDEXER|OLLAMA|GREENBONE|GVM|DATABASE|POSTGRES)", re.I), "public env var for an internal service"),
    (re.compile(r"/api/(generate|chat|tags)\b"), "Ollama API path"),
]


def _web_files():
    roots = [WEB / "src", WEB / "next.config.ts"]
    for r in roots:
        files = [r] if r.is_file() else [p for p in r.rglob("*") if p.suffix in {".ts", ".tsx", ".js", ".mjs"}]
        yield from files


def test_web_never_addresses_internal_services():
    hits = []
    for f in _web_files():
        text = f.read_text(encoding="utf-8", errors="replace")
        for rx, why in FORBIDDEN:
            for m in rx.finditer(text):
                hits.append(f"{f.relative_to(WEB)}: {why}: {m.group(0)[:60]}")
    assert hits == [], "\n".join(hits)


def test_only_the_versioned_api_is_proxied():
    cfg = (WEB / "next.config.ts").read_text(encoding="utf-8")
    sources = re.findall(r"source:\s*\"([^\"]+)\"", cfg)
    rewrites = [s for s in sources if s.startswith("/api")]
    assert rewrites == ["/api/v1/:path*"], rewrites


def test_foundation_client_calls_only_relative_api_v1_paths():
    client = (WEB / "src" / "foundation" / "api" / "client.ts").read_text(encoding="utf-8")
    paths = re.findall(r"'(/[^']*)'", client)
    assert paths and all(p.startswith("/api/v1/") for p in paths), paths
    assert "http://" not in client and "https://" not in client
