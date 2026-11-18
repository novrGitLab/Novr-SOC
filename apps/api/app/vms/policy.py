"""VMS organization scan policy and asset enrollment (domain logic; the HTTP layer is app.modules.vms).

Authorization model. A scan touches a target only when ALL of these hold, each checked when the scan is queued and again
when a worker claims it:
  1. the installation allows scanning (Settings.vms_scanning: local_test_targets in development, authorized_scopes in
     production);
  2. the organization has ENABLED its scan policy (authorization reference, at least one weekly window);
  3. the target is inside one of the organization's approved, unexpired scopes that allows the activity;
  4. the target is outside every protected network of the policy;
  5. the claim happens inside a policy window and under the policy's concurrency cap; the worker receives the policy's
     packet-rate ceiling and protected networks and enforces its own declared networks (services/vms-worker).

Enrollment replaces per-endpoint approval: an asset imported from a monitoring source (Wazuh agent, manual entry,
registered log source) is enrolled automatically when its address is private, fresh, unique in the organization and
inside an approved ip/cidr scope. It never widens a scope. Public addresses, addresses shared by two assets, addresses
not reported recently (dynamic assignment) and assets known only from scans are listed with the reason, never scanned
because they appeared in telemetry.
"""
from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import text
from sqlalchemy.engine import Connection

# Sources that establish that the organization owns the asset (not merely that a scanner saw an address).
OWNERSHIP_SOURCES = frozenset({"wazuh", "manual", "log_source", "collector"})
ENROLLMENT_ACTIVITY_KINDS = ("ip", "cidr")
REEVALUATE_AFTER = timedelta(hours=1)
CGNAT = ipaddress.ip_network("100.64.0.0/10")
# Documentation ranges (RFC 5737, RFC 3849): never an organization's own network, never a scan target.
DOCUMENTATION = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))


def _documentation(net) -> bool:
    return any(net.version == d.version and net.subnet_of(d) or (net.version == d.version and d.subnet_of(net)) for d in DOCUMENTATION)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------- policy
DEFAULTS = {"enabled": False, "auto_enroll": False, "enroll_activity": "ports", "rescan_interval_days": 7, "protected_networks": [],
            "windows": [], "timezone": "UTC", "max_targets_per_scan": 32, "max_rate_pps": 100, "max_concurrent_scans": 1,
            "address_max_age_hours": 72, "authorization_reference": "", "updated_by": None, "updated_at": None}


def load(conn: Connection) -> tuple[dict, bool]:
    """(policy of the active organization, configured?). Not configured = the defaults, which are disabled."""
    r = conn.execute(text("SELECT * FROM novrsoc.vms_scan_policies WHERE org_id = novrsoc.app_org()")).mappings().first()
    if r is None:
        return dict(DEFAULTS), False
    p = dict(r)
    p["protected_networks"] = [str(n) for n in (p["protected_networks"] or [])]
    p["windows"] = p["windows"] if isinstance(p["windows"], list) else json.loads(p["windows"] or "[]")
    return p, True


def tz(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError(f"unknown timezone {name!r}") from None


def in_window(policy: dict, now: datetime | None = None) -> bool:
    """Whether `now` falls inside one of the policy's weekly windows (in the policy's timezone). No window, no scan."""
    local = (now or _now()).astimezone(tz(policy["timezone"]))
    minute = local.hour * 60 + local.minute
    return any(w["weekday"] == local.weekday() and w["start_minute"] <= minute < w["end_minute"] for w in policy["windows"])


def parse_networks(values: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    out = []
    for v in values:
        try:
            out.append(ipaddress.ip_network(v.strip(), strict=False))
        except ValueError:
            raise ValueError(f"{v!r} is not an address or network") from None
    return out


def protected(address: str, networks: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip.version == n.version and ip in n for n in parse_networks(networks))


# ---------------------------------------------------------------- scope rules per installation mode
def production_scope_problem(kind: str, value: str) -> str | None:
    """Why a scope entry may not be approved in authorized_scopes mode (None = acceptable). Ranges are bounded, and
    addresses that never belong to a client network (loopback, link-local, multicast, reserved) are refused."""
    if kind in ("ip", "cidr"):
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return "not a valid address or range"
        first = net.network_address
        if _documentation(net):
            return "documentation address ranges are never scanned"
        if first.is_loopback or first.is_link_local or first.is_multicast or first.is_unspecified or first.is_reserved:
            return "loopback, link-local, multicast and reserved addresses cannot be scanned"
        limit = (16 if not first.is_global else 24) if net.version == 4 else (112 if not first.is_global else 120)
        if net.prefixlen < limit:
            return f"a range must be /{limit} or narrower ({'public' if first.is_global else 'private'} IPv{net.version})"
        return None
    host = value.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
    if host == "localhost" or host.endswith(".localhost") or "." not in host:
        return "a name must be a fully qualified domain"
    return None


# ---------------------------------------------------------------- enrollment
def address_holders(conn: Connection, address: str) -> int:
    """How many active assets of the organization report this IP address (as an identifier or their primary address)."""
    return conn.execute(text("""SELECT count(DISTINCT a.id) FROM novrsoc.assets a
                                WHERE a.status = 'active' AND a.merged_into IS NULL
                                  AND (host(a.primary_ip) = :v OR EXISTS (SELECT 1 FROM novrsoc.asset_identifiers i
                                       WHERE i.asset_id = a.id AND i.kind = 'ip' AND i.value = :v))"""), {"v": address}).scalar() or 0


def _scopes(conn: Connection, activity: str) -> list:
    rows = conn.execute(text("""SELECT id, kind, value FROM novrsoc.vms_scopes WHERE valid_until > now()
                                AND :a = ANY(allowed_activities) AND kind IN ('ip', 'cidr')"""), {"a": activity}).all()
    nets = []
    for r in rows:
        try:
            nets.append((ipaddress.ip_network(r.value, strict=False), r))
        except ValueError:
            continue
    return sorted(nets, key=lambda x: -x[0].prefixlen)   # most specific scope first


def decide(asset, addresses: list, shared: set[str], scopes: list, policy: dict, now: datetime,
           local_test_only: bool) -> tuple[str, str, str | None, uuid.UUID | None]:
    """(status, reason, address, scope_id) for one asset. Pure: every input is passed in (unit-tested)."""
    sources = set(asset.sources or [])
    if not sources & OWNERSHIP_SOURCES:
        return "unverified_source", "known only from scanning or third-party data; ownership is not established", None, None
    fresh_after = now - timedelta(hours=policy["address_max_age_hours"])
    ips = sorted(addresses, key=lambda x: x[1], reverse=True)   # (address, last_seen_at), newest first
    if not ips:
        return "no_address", "no IP address has been reported for this asset", None, None
    address, seen = ips[0]
    if seen < fresh_after:
        return "stale_address", (f"address last reported {seen:%Y-%m-%d %H:%M} UTC, older than {policy['address_max_age_hours']} h: "
                                 "it may since have been assigned to another device"), address, None
    ip = ipaddress.ip_address(address)
    if ip.version == 4 and ip in CGNAT:
        return "public_address", "carrier-grade NAT space is assigned by a provider, not by the organization", address, None
    if ip.is_global or _documentation(ipaddress.ip_network(address)):
        return "public_address", "public addresses are scanned only as explicit scan targets, never from telemetry", address, None
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified or (ip.is_loopback and not local_test_only):
        return "outside_scope", "not a scannable network address", address, None
    if address in shared:
        return "shared_address", "another asset of the organization reports the same address; resolve the duplicate first", address, None
    if protected(address, policy["protected_networks"]):
        return "excluded_protected", "inside a protected network of the scan policy", address, None
    scope = next((r for net, r in scopes if ip.version == net.version and ip in net), None)
    if scope is None:
        return "outside_scope", "inside no approved scan scope that allows the enrollment activity", address, None
    if not (policy["enabled"] and policy["auto_enroll"]):
        return "eligible", f"inside approved scope {scope.value}; automatic enrollment is off", address, scope.id
    return "enrolled", f"inside approved scope {scope.value}", address, scope.id


def evaluate(conn: Connection, *, local_test_only: bool = False) -> dict[str, int]:
    """Re-evaluate every active asset of the active organization. Manual exclusions stay. Returns counts by status."""
    policy, _ = load(conn)
    now = _now()
    scopes = _scopes(conn, policy["enroll_activity"])
    assets = conn.execute(text("""
        SELECT a.id, a.primary_ip, a.last_seen_at,
               (SELECT array_agg(DISTINCT src) FROM novrsoc.asset_identifiers i, unnest(i.sources) src WHERE i.asset_id = a.id) AS sources
          FROM novrsoc.assets a WHERE a.status = 'active' AND a.merged_into IS NULL""")).all()
    ips: dict[uuid.UUID, list] = {}
    for r in conn.execute(text("SELECT asset_id, value, last_seen_at FROM novrsoc.asset_identifiers WHERE kind = 'ip'")):
        ips.setdefault(r.asset_id, []).append((r.value, r.last_seen_at))
    for a in assets:
        if a.primary_ip is not None and not any(v == str(a.primary_ip) for v, _ in ips.get(a.id, [])):
            ips.setdefault(a.id, []).append((str(a.primary_ip), a.last_seen_at))
    owners: dict[str, set] = {}
    active = {a.id for a in assets}
    for aid, vals in ips.items():
        if aid in active:
            for v, _ in vals:
                owners.setdefault(v, set()).add(aid)
    shared = {v for v, s in owners.items() if len(s) > 1}
    manual = {r.asset_id for r in conn.execute(text("SELECT asset_id FROM novrsoc.vms_enrollments WHERE status = 'manual_exclusion'"))}
    counts: dict[str, int] = {}
    for a in assets:
        if a.id in manual:
            counts["manual_exclusion"] = counts.get("manual_exclusion", 0) + 1
            continue
        status, reason, address, scope_id = decide(a, ips.get(a.id, []), shared, scopes, policy, now, local_test_only)
        counts[status] = counts.get(status, 0) + 1
        conn.execute(text("""
            INSERT INTO novrsoc.vms_enrollments (org_id, asset_id, address, scope_id, status, reason, evaluated_at)
            VALUES (novrsoc.app_org(), :a, CAST(:ip AS inet), :s, :st, :r, now())
            ON CONFLICT (org_id, asset_id) DO UPDATE SET address = EXCLUDED.address, scope_id = EXCLUDED.scope_id,
              status = EXCLUDED.status, reason = EXCLUDED.reason, evaluated_at = now()"""),
            {"a": a.id, "ip": address, "s": scope_id, "st": status, "r": reason[:500]})
    return counts


def queue_enrollment_scans(conn: Connection, *, target_allowed) -> int:
    """Queue scans for enrolled assets that are due (never scanned, or older than the rescan interval) and not already in a
    queued or running enrollment scan. One job per scope, at most max_targets_per_scan targets each. The requester is the
    person who last saved the policy (the standing authorization); without one nothing is queued.
    `target_allowed(address)` applies the installation mode's target rule."""
    policy, configured = load(conn)
    if not (configured and policy["enabled"] and policy["auto_enroll"] and policy["updated_by"]):
        return 0
    last = conn.execute(text("SELECT max(evaluated_at) FROM novrsoc.vms_enrollments")).scalar()
    if last is None or last < _now() - REEVALUATE_AFTER:
        evaluate(conn)
    due = conn.execute(text("""
        SELECT e.asset_id, host(e.address) AS address, e.scope_id FROM novrsoc.vms_enrollments e
         WHERE e.status = 'enrolled' AND e.scope_id IS NOT NULL
           AND (e.last_scanned_at IS NULL OR e.last_scanned_at < now() - make_interval(days => :d))
           AND NOT EXISTS (SELECT 1 FROM novrsoc.vms_scan_jobs j WHERE j.origin = 'enrollment' AND j.state IN ('queued', 'running')
                           AND e.asset_id = ANY(j.asset_ids))
         ORDER BY e.last_scanned_at NULLS FIRST, e.asset_id"""), {"d": policy["rescan_interval_days"]}).all()
    by_scope: dict[uuid.UUID, list] = {}
    for r in due:
        if target_allowed(r.address) and not protected(r.address, policy["protected_networks"]):
            by_scope.setdefault(r.scope_id, []).append(r)
    made = 0
    for scope_id, rows in by_scope.items():
        size = policy["max_targets_per_scan"]
        for i in range(0, len(rows), size):
            chunk = rows[i:i + size]
            key = f"enroll-{scope_id}-{_now():%Y%m%d%H}-{i // size}"
            r = conn.execute(text("""
                INSERT INTO novrsoc.vms_scan_jobs (org_id, scope_id, activity, targets, profile, idempotency_key, requested_by, origin,
                                                   asset_ids, max_rate_pps, progress)
                VALUES (novrsoc.app_org(), :s, :a, :t, 'standard', :k, :u, 'enrollment', :ids, :rate, CAST(:pg AS jsonb))
                ON CONFLICT (org_id, idempotency_key) DO NOTHING RETURNING id"""),
                {"s": scope_id, "a": policy["enroll_activity"], "t": [x.address for x in chunk], "k": key, "u": policy["updated_by"],
                 "ids": [x.asset_id for x in chunk], "rate": policy["max_rate_pps"],
                 "pg": json.dumps({"targets_total": len(chunk), "targets_reported": 0, "outcomes": {}})}).first()
            made += 1 if r else 0
    return made
