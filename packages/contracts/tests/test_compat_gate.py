"""The v1 compatibility gate detects breaking changes and allows additive ones."""
import importlib.util
from pathlib import Path

import pytest

from novrsoc_contracts.v1 import operations

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("compat", ROOT / "scripts" / "contracts" / "compat.py")
compat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compat)

BASE = {"paths": {"/api/v1/sites": {"get": {}, "post": {}}},
        "components": {"schemas": {
            "Site": {"type": "object", "required": ["id", "name"],
                     "properties": {"id": {"type": "string", "format": "uuid"}, "name": {"type": "string"},
                                    "kind": {"enum": ["a", "b"], "type": "string"}}}}}}


def _with(**changes):
    import copy
    doc = copy.deepcopy(BASE)
    s = doc["components"]["schemas"]["Site"]
    for k, v in changes.items():
        if k == "drop_prop":
            s["properties"].pop(v)
        elif k == "prop":
            s["properties"].update(v)
        elif k == "required":
            s["required"] = v
        elif k == "drop_path":
            doc["paths"].pop(v)
        elif k == "drop_method":
            doc["paths"]["/api/v1/sites"].pop(v)
    return doc


def test_identical_and_additive_changes_pass():
    assert compat.compare_docs(BASE, BASE, "x") == []
    additive = _with(prop={"note": {"type": "string"}, "kind": {"enum": ["a", "b", "c"], "type": "string"}})
    additive["paths"]["/api/v1/new"] = {"get": {}}
    additive["components"]["schemas"]["NewThing"] = {"type": "object"}
    assert compat.compare_docs(BASE, additive, "x") == []


@pytest.mark.parametrize("change, needle", [
    ({"drop_prop": "name"}, "Site.name removed"),
    ({"prop": {"name": {"type": "integer"}}}, "type changed"),
    ({"required": ["id", "name", "kind"]}, "now required"),
    ({"prop": {"extra": {"type": "string"}}, "required": ["id", "name", "extra"]}, "added as REQUIRED"),
    ({"prop": {"kind": {"enum": ["a"], "type": "string"}}}, "enum values removed"),
    ({"drop_path": "/api/v1/sites"}, "path /api/v1/sites removed"),
    ({"drop_method": "post"}, "POST /api/v1/sites removed"),
])
def test_breaking_changes_fail(change, needle):
    problems = compat.compare_docs(BASE, _with(**change), "x")
    assert any(needle in p for p in problems), problems


def test_current_contracts_are_compatible_with_the_frozen_baseline():
    assert compat.main() == 0


def test_operations_contracts():
    from datetime import datetime, timezone
    import uuid
    from pydantic import ValidationError
    now = datetime.now(timezone.utc)
    base = dict(id=uuid.uuid4(), org_id=None, job_type="reports.generate", idempotency_key="job-0000000000000001",
                queued_at=now)
    operations.JobRun(**base, state="queued")
    with pytest.raises(ValidationError, match="finished_at"):
        operations.JobRun(**base, state="succeeded")
    with pytest.raises(ValidationError, match="retryable or permanent"):
        operations.JobRun(**base, state="failed", finished_at=now)
    with pytest.raises(ValidationError, match="next_attempt_at"):
        operations.JobRun(**base, state="failed", finished_at=now, failure="retryable")
    assert "org_id" not in operations.ComponentHeartbeat.model_fields
