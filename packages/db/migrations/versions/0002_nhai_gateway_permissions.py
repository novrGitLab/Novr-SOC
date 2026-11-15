"""NHAI and AI Gateway permissions (Phase 3, platform owner).

Adds exactly the three NHAI and AI Gateway permissions (docs/public/ARCHITECTURE.md), with their
proposed role mapping. No other permission is added or changed.

  nhai:analyze       request NHAI analysis (security-analysis lane)      super_admin, soc_manager, analyst
  nhai:review        accept/reject NHAI results, accept case-note drafts super_admin, soc_manager, analyst
  ai_gateway:manage  manage AI Gateway keys and quotas                   super_admin, soc_manager

Executives and portal users get no NHAI access in v1. tests/test_platform_guards.py asserts the database
catalogue equals app/authz/catalog.py.

Revision ID: 0002_nhai_gateway_permissions
Revises: 0001_foundation
Create Date: 2026-11-14
"""
from alembic import op

revision = "0002_nhai_gateway_permissions"
down_revision = "0001_foundation"
branch_labels = None
depends_on = None

PERMISSIONS = [
    ("nhai:analyze", "Request NHAI analysis of the active organisation's data (security-analysis lane)"),
    ("nhai:review", "Accept or reject NHAI results and accept NHAI case-note drafts"),
    ("ai_gateway:manage", "Manage AI Gateway keys, lanes, model allowlists and quotas"),
]
GRANTS = {
    "nhai:analyze": ["super_admin", "soc_manager", "analyst"],
    "nhai:review": ["super_admin", "soc_manager", "analyst"],
    "ai_gateway:manage": ["super_admin", "soc_manager"],
}


def _q(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def upgrade() -> None:
    op.execute("INSERT INTO novrsoc.permissions(key, description) VALUES " +
               ", ".join(f"({_q(k)}, {_q(d)})" for k, d in PERMISSIONS))
    op.execute("INSERT INTO novrsoc.role_permissions(role_key, permission_key) VALUES " +
               ", ".join(f"({_q(r)}, {_q(p)})" for p, roles in GRANTS.items() for r in roles))


def downgrade() -> None:
    keys = ", ".join(_q(k) for k, _ in PERMISSIONS)
    op.execute(f"DELETE FROM novrsoc.role_permissions WHERE permission_key IN ({keys})")
    op.execute(f"DELETE FROM novrsoc.permissions WHERE key IN ({keys})")
