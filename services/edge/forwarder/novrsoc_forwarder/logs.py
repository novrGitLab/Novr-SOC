"""Structured JSON logs on stdout (journald). Values that look like credentials are redacted; alert content is
never logged (only ids, counts and positions)."""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone

_PATTERNS = [
    (re.compile(r"nsk_[0-9a-f]{32}\.[A-Za-z0-9_-]+"), "nsk_[REDACTED]"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9\-._~+/]+=*"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|authorization)(\s*[:=]\s*)[^\s,;&\"']+"), r"\1\2[REDACTED]"),
]
_sink = sys.stdout


def redact(text: str) -> str:
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


def set_sink(sink) -> None:
    global _sink
    _sink = sink


def log(level: str, event: str, **fields) -> None:
    record = {"ts": datetime.now(timezone.utc).isoformat(), "level": level, "service": "novrsoc-forwarder", "event": event}
    for k, v in fields.items():
        record[k] = redact(v) if isinstance(v, str) else v
    _sink.write(json.dumps(record, default=str) + "\n")
    _sink.flush()
