"""Redaction (ported from NovrSOC@5054be3:backend/src/lib/__tests__/redact.test.ts). Every secret here is synthetic."""
import json
import time

from app.core.redact import FAILED, REDACTED, redact_string, redact_value

SECRET = "S3cr3t-Val_ue.9"  # gitleaks:allow (synthetic redaction test input)


def gone(text, *secrets):
    out = redact_string(text)
    assert out is not None, text
    for s in secrets:
        assert s not in out, f"{s!r} survived in {out!r}"
    assert "REDACTED" in out, out
    return out


def test_key_value_forms_every_key_any_case():
    for key in ["password", "PASSWORD", "Passwd", "secret", "client_secret", "token", "access_token", "X-Auth-Token",
                "api_key", "api-key", "APIKEY", "x-api-key", "authorization"]:
        gone(f"{key}={SECRET}", SECRET)
        gone(f"{key}: {SECRET}", SECRET)
        gone(f"{key} =   {SECRET} and more", SECRET)


def test_quoted_json_and_escaped_json():
    gone(f'{{"password":"{SECRET}","user":"bob"}}', SECRET)
    gone(f"{{'api_key': '{SECRET}'}}", SECRET)
    gone(f'{{\\"token\\":\\"{SECRET}\\",\\"x\\":1}}', SECRET)
    gone(f'password="with spaces {SECRET} inside"', SECRET)
    assert '"user":"bob"' in gone(f'{{"user":"bob","password":"{SECRET}"}}', SECRET)


def test_query_strings_headers_bearer_and_keys():
    out = gone(f"GET /login?user=bob&password={SECRET}&token=T0k3n&next=/home", SECRET, "T0k3n")
    assert "user=bob" in out and "next=/home" in out
    gone("Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA==")
    gone("authorization: Bearer eyJhbGciOi.payload.sig", "eyJhbGciOi.payload.sig")
    gone('curl -H "X: Bearer abc.def-ghi_jkl~mno+p/q=="', "abc.def-ghi_jkl~mno+p/q==")
    out = gone("before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEsecret\n-----END RSA PRIVATE KEY-----\nafter", "MIIEsecret")  # gitleaks:allow (synthetic)
    assert out.startswith("before") and out.endswith("after")
    gone("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz truncated", "b3BlbnNz")


def test_cli_flags_and_prose():
    gone(f"mysql --password {SECRET} -u root", SECRET)
    gone(f"setup.exe /apikey {SECRET}", SECRET)
    assert redact_string("sshd: Failed password for root") == "sshd: Failed password for root"
    assert redact_string("sshd: Failed password for invalid user admin from 203.0.113.4 port 22").endswith("port 22")


def test_idempotent_and_linear():
    once = redact_string(f'password={SECRET} Authorization: Bearer abc token="x"')
    assert redact_string(once) == once
    gone("password=REDACTEDhunter2", "hunter2")  # gitleaks:allow (synthetic redaction test input)
    started = time.time()
    for s in ["a" * 200_000, "password" * 20_000, "x=" * 50_000, '"' + "\\" * 100_000, "-----BEGIN PRIVATE KEY-----" + "A" * 100_000]:
        assert redact_string(s) is not None
    assert time.time() - started < 5


def test_structured_values():
    raw = {"full_log": f"Accepted password for root; token={SECRET}",
           "data": {"srcip": "203.0.113.4", "password": {"nested": SECRET}, "api_key": 12345,
                    "win": {"eventdata": {"commandLine": f"tool.exe --secret {SECRET} --apikey={SECRET}"}}},
           "list": [f"authorization: Basic {SECRET}", 7, None, True]}
    out = redact_value(raw)
    assert SECRET not in json.dumps(out)
    assert out["data"]["srcip"] == "203.0.113.4" and out["data"]["password"] == REDACTED and out["data"]["api_key"] == REDACTED
    assert out["list"][1:] == [7, None, True]


def test_failure_drops_instead_of_leaking():
    deep = cur = {}
    for _ in range(100):
        cur["x"] = {}
        cur = cur["x"]
    assert redact_value(deep) is FAILED
    assert redact_string(123) is None  # type: ignore[arg-type]
