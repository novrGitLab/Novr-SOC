"""Organization portals on ONE shared deployment: the host selects branding and restricts sign-in, never grants access.
Hostname spoofing, session binding, tenant isolation, branding, invitations, agent groups, installer links and onboarding."""
import base64
import re
import time
import uuid
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app import devseed
from app import portal as portals
from app.connectors import registry
from app.core.config import Settings
from app.main import create_app
from tests.conftest import PASSWORD, audit_actions
from tests.helpers.fake_manager import FakeManager

BASE = "novrsoc.test"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


@pytest.fixture(scope="module")
def manager():
    """A fake NovrSIEM manager; NovrSOC's enrollment client talks to it through a mock transport."""
    fake = FakeManager()
    previous = registry.enrollment_factory
    registry.enrollment_factory = lambda env, app_env: fake.client()
    registry.reset_enrollment()
    yield fake
    registry.enrollment_factory = previous
    registry.reset_enrollment()


@pytest.fixture(scope="module")
def papp(fixture_settings, manager):
    # rate limits are exercised separately (test_hardening.py): these tests share one client address
    return create_app(fixture_settings.model_copy(update={
        "portal_base_domain": BASE, "platform_hosts": "testserver,soc.novrsoc.test", "enrollment_mode": "manager_api",
        "agent_manager_address": "siem.novrsoc.test", "syslog_collector_address": "syslog.novrsoc.test",
        "public_platform_host": "soc.novrsoc.test", "rate_limits_enabled": False}))


@pytest.fixture(scope="module")
def tenants(owner, world):
    """Two fresh client organizations, each with a manager and an analyst at home."""
    out = {}
    with owner.begin() as c:
        for k in ("acme", "zeta"):
            tag = f"{k}{uuid.uuid4().hex[:5]}"
            org = devseed.create_org(c, tag, f"{k.title()} Ltd")
            out[k] = SimpleNamespace(id=org, slug=tag, sub=tag, mgr=f"mgr-{tag}@test.novrsoc.invalid", ana=f"ana-{tag}@test.novrsoc.invalid")
            devseed.create_user(c, out[k].mgr, PASSWORD, "soc_manager", org)
            devseed.create_user(c, out[k].ana, PASSWORD, "analyst", org)
    return out


def host(sub: str | None) -> str:
    return f"http://{sub}.{BASE}" if sub else "http://testserver"


def client(app, sub=None, email=None) -> TestClient:
    c = TestClient(app, base_url=host(sub))
    if email:
        r = c.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        assert r.status_code == 200, r.text
        c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return c


def admin(app) -> TestClient:
    return client(app, None, "admin@test.novrsoc.invalid")


def enable(app, t, **kw):
    r = admin(app).put(f"/api/v1/admin/organizations/{t.id}/portal",
                       json={"portal_subdomain": t.sub, "portal_enabled": True, "display_name": f"{t.slug} SOC", **kw})
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------- host resolution (unit)
def test_only_one_label_under_the_base_domain_is_a_portal():
    s = Settings(_env_file=None, env="test", database_url="postgresql+psycopg://a:b@127.0.0.1/x", portal_base_domain=BASE,
                 platform_hosts="testserver,soc.novrsoc.test")
    cases = {"acme.novrsoc.test": ("tenant", "acme"), "soc.novrsoc.test": ("platform", None), "testserver": ("platform", None),
             "a.b.novrsoc.test": ("unknown", None), "acme.novrsoc.test.evil.example": ("unknown", None), "novrsoc.test": ("unknown", None),
             "www.novrsoc.test": ("unknown", None), "api.novrsoc.test": ("unknown", None), "-x.novrsoc.test": ("unknown", None),
             "acme_1.novrsoc.test": ("unknown", None), "evil.example": ("unknown", None), "": ("unknown", None)}
    for h, want in cases.items():
        assert portals.classify(h, s) == want, h

    def req(headers):
        return SimpleNamespace(headers={k.lower(): v for k, v in headers.items()})
    assert portals.request_host(req({"Host": "ACME.novrsoc.test:3210"}), s) == "acme.novrsoc.test"
    assert portals.request_host(req({"Host": "acme.novrsoc.test."}), s) == "acme.novrsoc.test"
    assert portals.request_host(req({"Host": "testserver", "X-Forwarded-Host": "acme.novrsoc.test"}), s) == "testserver"   # not trusted
    trusted = s.model_copy(update={"trust_forwarded_host": True})
    assert portals.request_host(req({"Host": "127.0.0.1:8000", "X-Forwarded-Host": "acme.novrsoc.test"}), trusted) == "acme.novrsoc.test"
    with pytest.raises(Exception):
        Settings(_env_file=None, env="production", database_url="postgresql+psycopg://a:b@127.0.0.1/x", trust_forwarded_host=True)


# ---------------------------------------------------------------- branding
def test_branding_is_set_by_platform_administrators_and_public_only_where_enabled(papp, tenants, owner):
    t = tenants["acme"]
    assert client(papp, t.sub).get("/api/v1/portal").status_code == 404           # not enabled yet
    assert client(papp, None, t.mgr).put(f"/api/v1/admin/organizations/{t.id}/portal",
                                          json={"portal_subdomain": t.sub, "portal_enabled": True}).status_code == 403
    v = enable(papp, t, primary_color="#0B3D91", secondary_color="#f5a623")
    assert v["url"] == f"https://{t.sub}.{BASE}" and v["primary_color"] == "#0b3d91" and v["text_on_primary"] == "#ffffff"
    pub = client(papp, t.sub).get("/api/v1/portal").json()
    assert pub["kind"] == "tenant" and pub["organization"]["slug"] == t.slug and pub["branding"]["primary_color"] == "#0b3d91"
    assert set(pub) == {"kind", "organization", "branding"}                       # nothing beyond branding before sign-in
    assert client(papp).get("/api/v1/portal").json() == {"kind": "platform", "organization": None, "branding": None}
    assert client(papp, "nobody-here").get("/api/v1/portal").status_code == 404
    a = admin(papp)
    z = tenants["zeta"]
    taken = a.put(f"/api/v1/admin/organizations/{z.id}/portal", json={"portal_subdomain": t.sub, "portal_enabled": True})
    assert taken.status_code == 409 and taken.json()["error"]["code"] == "subdomain_taken"
    assert a.put(f"/api/v1/admin/organizations/{z.id}/portal", json={"portal_subdomain": "www", "portal_enabled": True}).status_code == 422
    with owner.connect() as c:
        platform = c.execute(text("SELECT id FROM novrsoc.organizations WHERE kind = 'platform'")).scalar()
    assert a.put(f"/api/v1/admin/organizations/{platform}/portal", json={"portal_subdomain": "plat", "portal_enabled": True}).status_code == 422
    # logos: raster only, and the bytes must be what they claim
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    assert a.put(f"/api/v1/admin/organizations/{t.id}/logo",
                 json={"content_type": "image/svg+xml", "data_base64": b64(b"<svg onload=alert(1)>")}).json()["error"]["code"] == "logo_type_not_allowed"
    assert a.put(f"/api/v1/admin/organizations/{t.id}/logo",
                 json={"content_type": "image/png", "data_base64": b64(b"GIF89a....")}).json()["error"]["code"] == "logo_content_mismatch"
    assert a.put(f"/api/v1/admin/organizations/{t.id}/logo",
                 json={"content_type": "image/png", "data_base64": b64(PNG + b"\x00" * 270_000)}).status_code == 422
    ok = a.put(f"/api/v1/admin/organizations/{t.id}/logo", json={"content_type": "image/png", "data_base64": b64(PNG)})
    assert ok.status_code == 200 and ok.json()["has_logo"]
    logo = client(papp, t.sub).get("/api/v1/portal/logo")
    assert logo.status_code == 200 and logo.content == PNG and logo.headers["content-type"] == "image/png"
    assert "sandbox" in logo.headers["content-security-policy"] and logo.headers["x-content-type-options"] == "nosniff"
    assert client(papp).get("/api/v1/portal/logo").status_code == 404
    assert client(papp, t.sub).get("/api/v1/portal").json()["branding"]["logo_url"].startswith("/api/v1/portal/logo?v=")
    acts = {e["action"] for e in audit_actions(owner)}
    assert {"ORG_PORTAL_UPDATED", "ORG_LOGO_UPDATED", "ORG_PORTAL_ENABLED"} <= acts


# ---------------------------------------------------------------- sign-in and session isolation
def test_each_portal_admits_only_its_own_members_and_sessions_never_change_host(papp, tenants, owner, world):
    t, z = tenants["acme"], tenants["zeta"]
    enable(papp, t)
    enable(papp, z)
    login = lambda sub, email: client(papp, sub).post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})  # noqa: E731
    assert login(t.sub, z.mgr).status_code == 401                                 # another organization's member: generic refusal
    assert login(t.sub, "admin@test.novrsoc.invalid").status_code == 401          # staff sign in on the platform address
    assert login(None, t.mgr).json()["error"]["code"] == "use_organization_portal"
    assert login("ghost", t.mgr).json()["error"]["code"] == "portal_not_found"
    c = client(papp, t.sub, t.mgr)
    me = c.get("/api/v1/auth/me").json()
    assert me["active_org"]["id"] == str(t.id) and me["home_org"]["id"] == str(t.id)
    cookie = "; ".join(f"{k}={v}" for k, v in c.cookies.items())
    for other in (None, z.sub):                                                    # a copied cookie on another host
        r = TestClient(papp, base_url=host(other)).get("/api/v1/auth/me", headers={"Cookie": cookie})
        assert r.status_code == 401
    spoof = TestClient(papp).get("/api/v1/auth/me", headers={"Cookie": cookie, "X-Forwarded-Host": f"{t.sub}.{BASE}"})
    assert spoof.status_code == 401                                                # forwarded host not trusted here
    assert c.get("/api/v1/soc/alerts", headers={"X-Org-Id": str(z.id)}).status_code == 403   # no switching on a portal
    assert c.get("/api/v1/command/scope").status_code == 403                       # the Command Center is for platform staff
    assert c.get("/api/v1/soc/alerts", headers={"X-Org-Id": str(t.id)}).status_code == 200
    # the platform session of a staff member is refused on a portal, and the Command Center still works on the platform
    a = admin(papp)
    assert a.get("/api/v1/command/scope").status_code == 200
    staff_cookie = "; ".join(f"{k}={v}" for k, v in a.cookies.items())
    assert TestClient(papp, base_url=host(t.sub)).get("/api/v1/auth/me", headers={"Cookie": staff_cookie}).status_code == 401
    mismatch = audit_actions(owner, action="SESSION_HOST_MISMATCH")
    assert len(mismatch) >= 3 and all(e["outcome"] == "denied" for e in mismatch)
    assert any(e["details"].get("reason") == "wrong_portal" for e in audit_actions(owner, action="LOGIN_FAILED"))
    # a portal switched off: its sessions stop working at once
    a.put(f"/api/v1/admin/organizations/{z.id}/portal", json={"portal_subdomain": z.sub, "portal_enabled": False})
    zc = TestClient(papp, base_url=host(z.sub))
    assert zc.get("/api/v1/portal").status_code == 404
    assert zc.post("/api/v1/auth/login", json={"email": z.mgr, "password": PASSWORD}).status_code == 404
    enable(papp, z)


# ---------------------------------------------------------------- invitations
def test_invitations_are_single_use_bound_to_their_portal_and_never_duplicate_accounts(papp, tenants, owner):
    t = tenants["acme"]
    enable(papp, t)
    a = admin(papp)
    email = f"ciso-{uuid.uuid4().hex[:6]}@acme.example"
    assert client(papp, t.sub, t.mgr).post(f"/api/v1/admin/organizations/{t.id}/invitations", json={"email": email}).status_code == 403
    r = a.post(f"/api/v1/admin/organizations/{t.id}/invitations", json={"email": email, "role": "soc_manager"})
    assert r.status_code == 201, r.text
    link = r.json()["link"]
    assert link.startswith(f"https://{t.sub}.{BASE}/invite#")
    token = link.split("#", 1)[1]
    with owner.connect() as c:                                                     # only the digest is stored
        stored = c.execute(text("SELECT token_hash FROM novrsoc.user_invitations WHERE id = :i"), {"i": r.json()["invitation"]["id"]}).scalar()
    assert token.encode() not in bytes(stored)
    assert a.post(f"/api/v1/admin/organizations/{t.id}/invitations", json={"email": email}).status_code == 409   # one open per email
    assert client(papp).post("/api/v1/invitations/preview", json={"token": token}).status_code == 404              # wrong address
    assert client(papp, tenants["zeta"].sub).post("/api/v1/invitations/preview", json={"token": token}).status_code == 404
    p = client(papp, t.sub).post("/api/v1/invitations/preview", json={"token": token}).json()
    assert p == {"state": "open", "email": email, "role": "soc_manager", "organization": f"{t.slug} SOC", "expires_at": p["expires_at"]}
    tc = client(papp, t.sub)
    assert tc.post("/api/v1/invitations/accept", json={"token": token, "display_name": "CISO", "password": "short"}).status_code == 422
    ok = tc.post("/api/v1/invitations/accept", json={"token": token, "display_name": "CISO", "password": "a long enough passphrase"})
    assert ok.status_code == 201 and ok.json()["sign_in_url"] == f"https://{t.sub}.{BASE}/login"
    assert tc.post("/api/v1/invitations/accept", json={"token": token, "display_name": "Again", "password": "a long enough passphrase"}).status_code == 404
    assert tc.post("/api/v1/invitations/preview", json={"token": token}).json() == {"state": "accepted", "email": None, "role": None,
                                                                                     "organization": None, "expires_at": None}
    signed = TestClient(papp, base_url=host(t.sub)).post("/api/v1/auth/login", json={"email": email, "password": "a long enough passphrase"})
    assert signed.status_code == 200 and signed.json()["session"]["active_org"]["id"] == str(t.id)
    # existing accounts are never duplicated; revoked and expired invitations do nothing
    assert a.post(f"/api/v1/admin/organizations/{t.id}/invitations", json={"email": email}).json()["error"]["code"] == "account_exists"
    other = a.post(f"/api/v1/admin/organizations/{t.id}/invitations", json={"email": f"x-{uuid.uuid4().hex[:6]}@acme.example"}).json()
    tok2 = other["link"].split("#", 1)[1]
    assert a.post(f"/api/v1/admin/organizations/{t.id}/invitations/{other['invitation']['id']}/revoke").json()["state"] == "revoked"
    assert tc.post("/api/v1/invitations/accept", json={"token": tok2, "display_name": "X", "password": "a long enough passphrase"}).status_code == 404
    third = a.post(f"/api/v1/admin/organizations/{t.id}/invitations", json={"email": f"y-{uuid.uuid4().hex[:6]}@acme.example"}).json()
    with owner.begin() as c:
        c.execute(text("UPDATE novrsoc.user_invitations SET created_at = now() - interval '5 days', expires_at = now() - interval '1 hour' "
                       "WHERE id = :i"), {"i": third["invitation"]["id"]})
    assert tc.post("/api/v1/invitations/preview", json={"token": third["link"].split("#", 1)[1]}).json()["state"] == "expired"
    listed = {i["email"]: i["state"] for i in a.get(f"/api/v1/admin/organizations/{t.id}/invitations").json()["items"]}
    assert listed[email] == "accepted" and listed[other["invitation"]["email"]] == "revoked"
    assert {"INVITATION_CREATED", "INVITATION_ACCEPTED", "INVITATION_REVOKED", "INVITATION_REFUSED"} <= {e["action"] for e in audit_actions(owner)}


# ---------------------------------------------------------------- agent group, installer links, onboarding
def test_enrollment_is_server_controlled_organization_bound_and_password_free(papp, tenants, owner, manager):
    """NovrSOC registers every agent itself, in the organization's provisioned group (as its ONLY group), against a ticket
    that is organization-bound, OS-bound, expiring, use-limited and revocable. No password, no self-chosen group."""
    t, z = tenants["acme"], tenants["zeta"]
    enable(papp, t)
    enable(papp, z)
    m = client(papp, t.sub, t.mgr)
    st = m.get("/api/v1/onboarding/status").json()
    if not st["agent_group"]["provisioned"]:
        assert st["installer_available"] is False and "provisioned" in st["installer_reason"]
        assert m.post("/api/v1/onboarding/installer", json={"os": "linux"}).json()["error"]["code"] == "installer_unavailable"
    a = admin(papp)
    assert m.post(f"/api/v1/admin/organizations/{t.id}/agent-group").status_code == 403
    g = a.post(f"/api/v1/admin/organizations/{t.id}/agent-group").json()
    assert re.fullmatch(rf"nv-{t.slug}-[a-z2-9]{{8}}", g["group_name"]) and g["on_manager"] is True
    assert g["group_name"] in manager.groups                                          # created on the manager by NovrSOC
    assert a.post(f"/api/v1/admin/organizations/{t.id}/agent-group").json()["group_name"] == g["group_name"]     # idempotent
    zg = a.post(f"/api/v1/admin/organizations/{z.id}/agent-group").json()["group_name"]
    assert zg != g["group_name"]
    st = m.get("/api/v1/onboarding/status").json()
    assert st["installer_available"] and st["enrollment"]["manager_version"] == "4.9.2" and st["enrollment"]["agent_version"] == "4.9.2"
    assert st["syslog"]["address"] == "syslog.novrsoc.test" and st["portal_url"] == f"https://{t.sub}.{BASE}"
    assert client(papp, t.sub, t.ana).post("/api/v1/onboarding/installer", json={"os": "linux"}).status_code == 403   # endpoints:manage
    cmds = {o: m.post("/api/v1/onboarding/installer", json={"os": o, "endpoints": 2}).json() for o in ("linux", "macos", "windows")}
    for o, c in cmds.items():
        assert f"https://{t.sub}.{BASE}/api/v1/install/novragent." in c["command"], o
        assert "wazuh" not in c["command"].lower() and "password" not in c["command"].lower() and c["max_endpoints"] == 2
    path = lambda o: re.search(r'"(https://[^"]+)"', cmds[o]["command"]).group(1).split(BASE, 1)[1]  # noqa: E731
    ticket = path("linux").split("t=", 1)[1]
    r = client(papp, t.sub).get(path("linux"))
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    assert f"TICKET='{ticket}'" in r.text and f"ENROLL_URL='https://{t.sub}.{BASE}/api/v1/install/enroll'" in r.text
    assert "MANAGER='siem.novrsoc.test'" in r.text and "VERSION='4.9.2'" in r.text and "manage_agents" in r.text
    for absent in ("REGISTRATION_PASSWORD", "AGENT_GROUP", g["group_name"], "Enrollment password"):
        assert absent not in r.text, absent                                           # no password, and the group is assigned by NovrSOC
    assert "gpgcheck=1" in r.text and "check-signature" in r.text                 # vendor signatures are verified
    win = client(papp, t.sub).get(path("windows"))
    assert win.status_code == 200 and "Get-AuthenticodeSignature" in win.text and "manage_agents.exe" in win.text and "Read-Host" not in win.text
    # refused downloads: another host, a tampered ticket, the wrong script, a suspended organization
    assert client(papp).get(path("linux")).status_code == 404
    assert client(papp, z.sub).get(path("linux")).status_code == 404
    assert client(papp, t.sub).get(path("linux")[:-3] + "AAA").status_code == 404
    assert client(papp, t.sub).get(path("linux").replace("novragent.sh", "novragent.ps1")).status_code == 404
    # enrollment: NovrSOC registers the endpoint, ONLY in the organization's group, and counts the ticket's endpoints
    enroll = lambda sub, tk, host, os_="linux": client(papp, sub).post("/api/v1/install/enroll", json={"ticket": tk, "hostname": host, "os": os_})  # noqa: E731
    assert enroll(None, ticket, "web01").status_code == 404                        # not at the platform address
    assert enroll(z.sub, ticket, "web01").status_code == 404                       # not at another organization's portal
    assert enroll(t.sub, ticket, "web01", "windows").status_code == 404            # the ticket is for Linux
    one = enroll(t.sub, ticket, "web01")
    assert one.status_code == 201 and one.headers["cache-control"] == "no-store", one.text
    aid = one.json()["agent_id"]
    assert manager.agents[aid]["groups"] == [g["group_name"]] and one.json()["name"] == f"{t.slug}-web01"
    two = enroll(t.sub, ticket, "web01")                                          # same host name: a distinct agent name
    assert two.status_code == 201 and two.json()["name"] == f"{t.slug}-web01-2"
    assert enroll(t.sub, ticket, "web02").status_code == 404                       # the ticket admitted 2 endpoints
    assert client(papp, t.sub).get(path("linux")).status_code == 404               # used up: no more downloads either
    listed = {x["id"]: x for x in m.get("/api/v1/onboarding/tickets").json()["items"]}
    assert listed[cmds["linux"]["ticket_id"]]["state"] == "used_up" and listed[cmds["linux"]["ticket_id"]]["uses"] == 2
    zm = client(papp, z.sub, z.mgr)
    assert all(x["id"] not in listed for x in zm.get("/api/v1/onboarding/tickets").json()["items"])
    # revocation and expiry
    mac = path("macos").split("t=", 1)[1]
    assert client(papp, t.sub, t.ana).post(f"/api/v1/onboarding/tickets/{cmds['macos']['ticket_id']}/revoke").status_code == 403
    assert m.post(f"/api/v1/onboarding/tickets/{cmds['macos']['ticket_id']}/revoke").json()["state"] == "revoked"
    assert enroll(t.sub, mac, "mbp", "macos").status_code == 404
    win_ticket = path("windows").split("t=", 1)[1]
    with owner.begin() as c:
        c.execute(text("UPDATE novrsoc.agent_enrollment_tickets SET created_at = now() - interval '3 hours', expires_at = now() - interval '1 minute' "
                       "WHERE id = :i"), {"i": cmds["windows"]["ticket_id"]})
    assert enroll(t.sub, win_ticket, "pc01", "windows").status_code == 404
    # a group assignment the manager refuses: the agent is removed again, nothing is counted
    fresh = m.post("/api/v1/onboarding/installer", json={"os": "linux", "endpoints": 1}).json()
    tk = re.search(r"t=([A-Za-z0-9_-]+)", fresh["command"]).group(1)
    before = set(manager.agents)
    manager.fail_group_assignment = True
    try:
        assert enroll(t.sub, tk, "db01").status_code == 502
    finally:
        manager.fail_group_assignment = False
    assert set(manager.agents) == before                                         # never left outside its organization's group
    assert enroll(t.sub, tk, "db01").status_code == 201                            # the ticket was not consumed by the failure
    with owner.begin() as c:
        c.execute(text("UPDATE novrsoc.organizations SET status = 'suspended' WHERE id = :o"), {"o": t.id})
    try:
        late = m.post  # the session's organization is suspended: sign-in context aside, public enrollment refuses
        assert client(papp, t.sub).get(path("windows")).status_code == 404
    finally:
        with owner.begin() as c:
            c.execute(text("UPDATE novrsoc.organizations SET status = 'active' WHERE id = :o"), {"o": t.id})
    assert late
    st = m.get("/api/v1/onboarding/status").json()
    assert st["enrollment"]["enrolled_agents"] == 3
    with owner.connect() as c:
        rows = c.execute(text("SELECT org_id, group_name FROM novrsoc.agent_enrollments WHERE agent_id = ANY(:a)"),
                         {"a": list(manager.agents)}).all()
    assert rows and all(r.org_id == t.id and r.group_name == g["group_name"] for r in rows)
    acts = {e["action"] for e in audit_actions(owner, org=t.id)}
    assert {"AGENT_ENROLLMENT_TICKET_ISSUED", "AGENT_INSTALLER_DOWNLOADED", "AGENT_ENROLLED", "AGENT_ENROLLMENT_FAILED",
            "AGENT_ENROLLMENT_TICKET_REVOKED"} <= acts


def test_onboarding_status_and_senders_stay_inside_the_organization(papp, tenants, owner):
    t, z = tenants["acme"], tenants["zeta"]
    enable(papp, t)
    enable(papp, z)
    m = client(papp, t.sub, t.mgr)
    ip = f"10.{uuid.uuid4().int % 200 + 20}.7.{uuid.uuid4().int % 250 + 1}"
    src = m.post("/api/v1/log-sources", json={"name": f"opnsense-{uuid.uuid4().hex[:4]}", "kind": "syslog", "source_ip": ip, "host": "",
                                              "device_type": "firewall", "vendor": "OPNsense", "protocol": "udp", "port": 514,
                                              "site_id": None, "network": None, "authorization_reference": "Onboarding guide",
                                              "notes": "", "enabled": True})
    assert src.status_code == 201 and src.json()["status"] == "pending_verification" and src.json()["enabled"] is False
    st = m.get("/api/v1/onboarding/status").json()
    assert st["sources"]["pending_verification"] >= 1 and st["organization"]["slug"] == t.slug
    zs = client(papp, z.sub, z.mgr)
    assert all(s["id"] != src.json()["id"] for s in zs.get("/api/v1/log-sources").json()["items"])
    assert zs.get("/api/v1/onboarding/status").json()["sources"]["pending_verification"] == 0
    dup = zs.post("/api/v1/log-sources", json={**{k: v for k, v in src.json().items() if k in ("kind", "host", "device_type", "vendor",
                                                                                                  "protocol", "port", "authorization_reference")},
                                                "name": "claim", "source_ip": ip, "site_id": None, "network": None, "notes": "", "enabled": True})
    assert dup.status_code == 409 and t.slug not in dup.text                       # one sender, one organization; owner not revealed
    assert TestClient(papp, base_url=host(t.sub)).get("/api/v1/onboarding/status").status_code == 401
