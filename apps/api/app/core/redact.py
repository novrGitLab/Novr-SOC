"""Redaction of untrusted log text before it leaves its store (NHAI prompts, evidence views, logs).

Ported from NovrSOC@5054be3:backend/src/lib/redact.ts (same patterns and rules; tests ported from
lib/__tests__/redact.test.ts into tests/test_redact.py).

Masks: values of keys naming a secret (password, passwd, secret, token, api_key/api-key/apikey,
authorization) in key=value / key: value / JSON / escaped-JSON / query-string forms and as object keys;
whole Authorization header values; bearer tokens anywhere; command-line flags naming a secret followed by
a value; PEM private-key blocks (also unterminated).
Never raises. When redaction fails for a value, the value is dropped (None), never returned unredacted.
The patterns are linear (no nested quantifiers; keys match only from the start of a token).
"""
from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

SECRET_KEY = re.compile(r"password|passwd|secret|token|api[_-]?key|authorization", re.I)
PRIVATE_KEY_BLOCK = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|$)")
AUTH_HEADER = re.compile(r"""(authorization\\?["']?\s*[:=]\s*)(\\?["']?)[^\r\n"'\\,;&}]*""", re.I)
BEARER = re.compile(r"\b(bearer)(\s+)[A-Za-z0-9\-._~+/]+=*", re.I)
KEY_VALUE = re.compile(
    r"""(?<![A-Za-z0-9_.\-])([A-Za-z0-9_.\-]{1,128})(\\?["']?)(\s*[:=]\s*)"""
    r"""("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\\"(?:[^"\\]|\\[^"])*\\"|[^\s&,;"'}\]\\]+)""")
ALREADY_MASKED = {REDACTED, "[REDACTED", f'"{REDACTED}"', f"'{REDACTED}'", f'\\"{REDACTED}\\"'}
CLI_FLAG = re.compile(r"""(?<![A-Za-z0-9_.\-])((?:--?|/)[A-Za-z0-9_.\-]{1,128})(\s+)("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s"']+)""")
MAX_DEPTH = 64


def _mask_quoted(value: str) -> str:
    if value.startswith('\\"'):
        return f'\\"{REDACTED}\\"'
    if value.startswith('"'):
        return f'"{REDACTED}"'
    if value.startswith("'"):
        return f"'{REDACTED}'"
    return REDACTED


def redact_string(text: str) -> str | None:
    """Redacts one string. None = redaction failed; the caller must drop the value."""
    try:
        if not isinstance(text, str):
            return None
        s = PRIVATE_KEY_BLOCK.sub(f"{REDACTED} PRIVATE KEY", text)
        s = AUTH_HEADER.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", s)
        s = BEARER.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", s)
        s = KEY_VALUE.sub(lambda m: (f"{m.group(1)}{m.group(2)}{m.group(3)}{_mask_quoted(m.group(4))}"
                                     if SECRET_KEY.search(m.group(1)) and m.group(4) not in ALREADY_MASKED else m.group(0)), s)
        s = CLI_FLAG.sub(lambda m: (f"{m.group(1)}{m.group(2)}{_mask_quoted(m.group(3))}"
                                    if SECRET_KEY.search(m.group(1)) and m.group(3) not in ALREADY_MASKED
                                    and not m.group(3).startswith("-") else m.group(0)), s)
        return s
    except Exception:
        return None


class _Fail(Exception):
    pass


def _walk(v: Any, depth: int) -> Any:
    if depth > MAX_DEPTH:
        raise _Fail("too deep")
    if isinstance(v, str):
        r = redact_string(v)
        if r is None:
            raise _Fail("string")
        return r
    if v is None or isinstance(v, (bool, int, float)):
        return v
    if isinstance(v, (list, tuple)):
        return [_walk(x, depth + 1) for x in v]
    if isinstance(v, dict):
        return {str(k): (REDACTED if SECRET_KEY.search(str(k)) else _walk(val, depth + 1)) for k, val in v.items()}
    return None


_FAILED = object()


def redact_value(v: Any) -> Any:
    """Redacts every string in a JSON-like value and masks every secret-named key's value.
    Returns the module sentinel FAILED when redaction fails; the caller must omit the field."""
    try:
        return _walk(v, 0)
    except Exception:
        return _FAILED


FAILED = _FAILED
