"""Production-path checks for scripts/release/rehearse_server2.sh, against the LOCAL rehearsal stack (loopback ports
18000 and 13210 only; never a real server). Prints PASS/FAIL per step and never prints a password or token."""
import http.client
import json
import sys

API, WEB = ("127.0.0.1", 18000), ("127.0.0.1", 13210)
results = []


def step(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))


class Client:
    def __init__(self, hostport):
        self.hostport, self.cookies = hostport, {}

    def req(self, method, path, body=None, csrf=True):
        c = http.client.HTTPConnection(*self.hostport, timeout=20)
        h = {"Content-Type": "application/json"}
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if csrf and method != "GET" and "novrsoc_csrf" in self.cookies:
            h["X-CSRF-Token"] = self.cookies["novrsoc_csrf"]
        c.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
        r = c.getresponse()
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                name, _, rest = v.partition("=")
                val = rest.split(";", 1)[0]
                if val:
                    self.cookies[name] = val
                else:
                    self.cookies.pop(name, None)
        raw = r.read()
        try:
            data = json.loads(raw) if raw else None
        except ValueError:
            data = raw[:200]
        return r.status, data, dict((k.lower(), v) for k, v in r.getheaders())


def main(email, temp):
    anon = Client(API)
    st, body, _ = anon.req("GET", "/readyz")
    step("readyz is ready (database, migrations at head)", st == 200 and body["status"] == "ready", json.dumps([c["name"] for c in body["checks"]]))
    st, _, _ = anon.req("GET", "/api/docs")
    step("interactive API docs are disabled in production", st == 404, str(st))

    a = Client(API)
    st, body, hdr = a.req("POST", "/api/v1/auth/login", {"email": email, "password": temp})
    secure = "secure" in hdr.get("set-cookie", "").lower()
    step("first administrator signs in with the bootstrap password; cookies are Secure",
         st == 200 and body["session"]["password_change_required"] is True and secure, str(st))
    st, body, _ = a.req("GET", "/api/v1/sites")
    step("everything else is refused until the temporary password is changed",
         st == 403 and body["error"]["code"] == "password_change_required", str(st))
    new = "rehearsal passphrase " + __import__("secrets").token_urlsafe(12)
    st, _, _ = a.req("POST", "/api/v1/auth/password", {"current_password": temp, "new_password": new})
    step("the administrator sets their own password", st == 204, str(st))
    st, body, _ = a.req("GET", "/api/v1/platform/status")
    states = {c["connector"]: c["state"] for c in body.get("connectors", [])} if st == 200 else {}
    step("platform status: every connector is unconfigured, none connected",
         st == 200 and states and all(v == "unconfigured" for v in states.values()), json.dumps(states))
    st, org, _ = a.req("POST", "/api/v1/admin/organizations", {"slug": "rehearsal-client", "name": "Rehearsal Client"})
    step("a client organization is created through Tenants and users", st in (200, 201), str(st))
    st, u, _ = a.req("POST", "/api/v1/admin/users", {"email": "analyst@rehearsal.invalid", "role": "analyst"})
    step("a user is created with a one-time temporary password", st == 201 and len(u.get("temporary_password", "")) >= 20, str(st))
    st, _, _ = a.req("POST", "/api/v1/sites", {"name": "no-csrf"}, csrf=False)
    step("a state-changing request without the CSRF header is refused", st == 403, str(st))

    w = Client(WEB)
    st, _, hdr = w.req("GET", "/login")
    step("web serves the sign-in page with security headers",
         st == 200 and hdr.get("x-frame-options") == "DENY" and "strict-transport-security" in hdr and "x-powered-by" not in hdr, str(st))
    st, body, _ = w.req("GET", "/api/v1/auth/me")
    step("web rewrites /api/v1 to the api service (unauthenticated -> 401 from the API)", st == 401, str(st))
    st, body, _ = w.req("POST", "/api/v1/auth/login", {"email": email, "password": new})
    step("sign-in through the web origin with the new password", st == 200, str(st))
    return all(results)


if __name__ == "__main__":
    ok = main(sys.argv[1], open(sys.argv[2]).read().strip())
    print(f"\n{sum(results)}/{len(results)} steps passed")
    sys.exit(0 if ok else 1)
