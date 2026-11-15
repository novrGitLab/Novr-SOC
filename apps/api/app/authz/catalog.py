"""Role → permission catalogue. Source of truth for the API.

Ported from legacy lib/permissions.ts (ROLE_PERMISSIONS), plus the V2 foundation permissions
org:read, sites:*, audit:read and service_identities:manage. Migration 0001 seeds the same data into
novrsoc.roles / permissions / role_permissions; tests/test_catalog.py asserts the two are identical.

CNII permissions are necessary but NOT sufficient: CNII access also needs an explicit, unexpired
designation (app/authz/cnii.py).
"""
from __future__ import annotations

FOUNDATION = ["org:read", "sites:read", "sites:manage", "audit:read", "service_identities:manage"]
# Migration 0002: NHAI and AI Gateway (docs/public/ARCHITECTURE.md).
NHAI = ["nhai:analyze", "nhai:review", "ai_gateway:manage"]
# Phase 4 (migrations 0003, 0005): endpoint management and reports.
ENDPOINTS = ["endpoints:read", "endpoints:manage"]
REPORTS = ["reports:read", "reports:manage"]
# Pilot (migration 0010): SOAR management, Email Security / Brand Protection, administration, backups.
PILOT = ["soar:manage", "protection:read", "protection:manage", "users:manage", "backups:read"]
# Consolidation (migration 0012): asset inventory, SLA, NovrChat, data continuity, billing, exports, platform health.
CONSOLIDATION = ["assets:read", "assets:manage", "sla:manage", "chat:use", "recovery:read", "recovery:manage",
                 "billing:manage", "exports:manage", "platform:monitor"]
LEGACY = ["alerts:read", "alerts:triage", "cases:read", "cases:write", "cases:close", "response:contain",
          "response:approve", "handover:write", "vms:read", "vms:scan", "vms:scope", "vms:manage",
          "intel:read", "intel:manage", "cnii:read", "cnii:manage", "cnii:sector", "vms:client", "secops:client"]
PERMISSIONS: tuple[str, ...] = tuple(FOUNDATION + LEGACY + NHAI + ENDPOINTS + REPORTS + PILOT + CONSOLIDATION)

STAFF_ROLES = ("super_admin", "soc_manager", "analyst")
ROLES = ("super_admin", "soc_manager", "analyst", "executive", "portal_user")

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "super_admin": frozenset(PERMISSIONS),
    "soc_manager": frozenset(p for p in PERMISSIONS if p not in ("users:manage", "backups:read", "billing:manage", "platform:monitor")),
    "analyst": frozenset(["org:read", "sites:read", "alerts:read", "alerts:triage", "cases:read", "cases:write",
                          "cases:close", "response:contain", "handover:write", "vms:read", "vms:scan", "vms:manage",
                          "intel:read", "intel:manage", "cnii:read", "cnii:sector", "nhai:analyze", "nhai:review",
                          "endpoints:read", "reports:read", "reports:manage", "protection:read", "protection:manage",
                          "assets:read", "assets:manage", "chat:use", "recovery:read"]),
    "executive": frozenset(["org:read", "sites:read", "vms:read", "intel:read", "cnii:read", "endpoints:read",
                            "reports:read", "protection:read", "assets:read", "chat:use", "recovery:read"]),
    "portal_user": frozenset(["org:read", "vms:client", "secops:client"]),
}


def permissions_for(role: str | None) -> frozenset[str]:
    """Unknown roles hold nothing."""
    return ROLE_PERMISSIONS.get(role or "", frozenset())
