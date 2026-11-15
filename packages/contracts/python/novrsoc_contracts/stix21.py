"""STIX 2.1 validation and normalization (standard library only; shared by the API and the Server 1 Threat Insights
service, which imports this single module without pydantic).

validate_object(obj) -> list of problems ([] = valid) for the object types NovrSOC uses, against the STIX 2.1
specification's REQUIRED properties and formats (OASIS STIX 2.1, section 3 and the per-type sections):
  common: type, spec_version == "2.1", id "<type>--<UUID>", created/modified timestamps (modified >= created)
  indicator (pattern, pattern_type, valid_from; valid_until > valid_from), malware (name, is_family),
  threat-actor (name), attack-pattern (name), campaign (name), intrusion-set (name), identity (name),
  tool (name), vulnerability (name), report (name, published, object_refs), relationship (relationship_type,
  source_ref, target_ref as identifiers), sighting (sighting_of_ref), marking-definition (common id/created only).
normalize_bundle(bundle) -> (objects, rejected): valid objects (deduplicated by (id, modified), newest kept) and
"<id>: <reason>" strings. Relationship endpoints must be identifiers of known SDO/SCO types.
"""
from __future__ import annotations

import re
from datetime import datetime

ID = re.compile(r"^([a-z][a-z0-9-]+)--[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
REQUIRED = {
    "indicator": ("pattern", "pattern_type", "valid_from"),
    "malware": ("name", "is_family"),
    "threat-actor": ("name",), "attack-pattern": ("name",), "campaign": ("name",), "intrusion-set": ("name",),
    "identity": ("name",), "tool": ("name",), "vulnerability": ("name",),
    "report": ("name", "published", "object_refs"),
    "relationship": ("relationship_type", "source_ref", "target_ref"),
    "sighting": ("sighting_of_ref",),
    "marking-definition": (),
}
SUPPORTED = set(REQUIRED)
REL_TYPE = re.compile(r"^[a-z0-9-]{1,100}$")


def _dt(v) -> datetime | None:
    if not isinstance(v, str) or not TS.match(v):
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None


def validate_object(obj) -> list[str]:
    if not isinstance(obj, dict):
        return ["not an object"]
    t = obj.get("type")
    if t not in SUPPORTED:
        return [f"unsupported type {t!r}"]
    problems = []
    if obj.get("spec_version") != "2.1":
        problems.append("spec_version must be 2.1")
    m = ID.match(str(obj.get("id", "")))
    if not m or m.group(1) != t:
        problems.append("id must be '<type>--<UUID>' for this type")
    created, modified = _dt(obj.get("created")), _dt(obj.get("modified"))
    if t != "marking-definition":
        if created is None or modified is None:
            problems.append("created and modified must be STIX timestamps (YYYY-MM-DDTHH:MM:SS[.s]Z)")
        elif modified < created:
            problems.append("modified is earlier than created")
    elif created is None:
        problems.append("created must be a STIX timestamp")
    for prop in REQUIRED[t]:
        if prop not in obj or obj[prop] in (None, "", []):
            problems.append(f"required property {prop!r} is missing")
    if t == "indicator":
        vf, vu = _dt(obj.get("valid_from")), _dt(obj.get("valid_until")) if obj.get("valid_until") else None
        if vf is None:
            problems.append("valid_from must be a STIX timestamp")
        if obj.get("valid_until") is not None and (vu is None or (vf and vu <= vf)):
            problems.append("valid_until must be a timestamp after valid_from")
    if t == "malware" and not isinstance(obj.get("is_family"), bool):
        problems.append("is_family must be a boolean")
    if t == "relationship":
        if not REL_TYPE.match(str(obj.get("relationship_type", ""))):
            problems.append("relationship_type is not valid")
        for ref in ("source_ref", "target_ref"):
            rm = ID.match(str(obj.get(ref, "")))
            if not rm or rm.group(1) in ("relationship", "sighting", "marking-definition"):
                problems.append(f"{ref} must reference an SDO/SCO identifier")
    if t == "sighting" and not ID.match(str(obj.get("sighting_of_ref", ""))):
        problems.append("sighting_of_ref must be an identifier")
    if t == "report" and not all(ID.match(str(r)) for r in obj.get("object_refs") or []):
        problems.append("object_refs must be identifiers")
    return problems


def normalize_bundle(bundle) -> tuple[list[dict], list[str]]:
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        return [], ["not a STIX 2.1 bundle"]
    if bundle.get("id") is not None and not str(bundle.get("id")).startswith("bundle--"):
        return [], ["bundle id must start with 'bundle--'"]
    newest: dict[str, dict] = {}
    rejected: list[str] = []
    for obj in bundle["objects"][:10_000]:
        problems = validate_object(obj)
        oid = str(obj.get("id", "?"))[:120] if isinstance(obj, dict) else "?"
        if problems:
            rejected.append(f"{oid}: {problems[0]}")
            continue
        prev = newest.get(obj["id"])
        if prev is None or (obj.get("modified") or "") > (prev.get("modified") or ""):
            newest[obj["id"]] = obj
    return list(newest.values()), rejected
