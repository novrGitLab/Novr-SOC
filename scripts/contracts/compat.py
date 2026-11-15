"""v1 contract compatibility gate (platform-owned).

Compares the generated documents in packages/contracts/openapi/ against the APPROVED baseline frozen in
packages/contracts/baseline/v1/. Within v1 only additive changes are allowed:

  BREAKING (fails):  a removed HTTP path or method; a removed schema; a removed property; a property that
                     becomes required; a NEW required property on an existing schema; a changed type or $ref;
                     a removed enum value.
  ALLOWED:           new paths, new schemas, new optional properties, new enum values, description changes.

  python scripts/contracts/compat.py                   check (exit 1 on breaking changes)
  python scripts/contracts/compat.py --freeze          (platform owner only) re-freeze the baseline after an
                                                       approved, versioned change
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CURRENT = ROOT / "packages" / "contracts" / "openapi"
BASELINE = ROOT / "packages" / "contracts" / "baseline" / "v1"
DOCS = ("novrsoc-api.v1.json", "novrsoc-contracts.v1.json")


def _shape(schema: dict) -> object:
    """Comparable type signature of a property schema (ignores descriptions, titles, defaults, bounds)."""
    if "$ref" in schema:
        return ("ref", schema["$ref"].rsplit("/", 1)[-1])
    if "anyOf" in schema or "oneOf" in schema:
        return ("union", tuple(sorted(str(_shape(s)) for s in schema.get("anyOf", schema.get("oneOf", [])))))
    if "allOf" in schema and len(schema["allOf"]) == 1:
        return _shape(schema["allOf"][0])
    t = schema.get("type")
    if t == "array":
        return ("array", _shape(schema.get("items", {})))
    if "const" in schema:
        return ("const", json.dumps(schema["const"]))
    if "enum" in schema:
        return ("enum", t)
    return ("type", t, schema.get("format"))


def _enum_values(schema: dict) -> set:
    vals = set(json.dumps(v) for v in schema.get("enum", []))
    for s in schema.get("anyOf", []) + schema.get("oneOf", []):
        vals |= _enum_values(s)
    return vals


def compare_schemas(base: dict, cur: dict, where: str) -> list[str]:
    problems = []
    for name, b in base.items():
        c = cur.get(name)
        if c is None:
            problems.append(f"{where}: schema {name} removed")
            continue
        if "enum" in b:
            removed = _enum_values(b) - _enum_values(c)
            if removed:
                problems.append(f"{where}: {name}: enum values removed {sorted(removed)}")
        bprops, cprops = b.get("properties", {}), c.get("properties", {})
        breq, creq = set(b.get("required", [])), set(c.get("required", []))
        for p, bs in bprops.items():
            if p not in cprops:
                problems.append(f"{where}: {name}.{p} removed")
                continue
            if _shape(bs) != _shape(cprops[p]):
                problems.append(f"{where}: {name}.{p} type changed {_shape(bs)} -> {_shape(cprops[p])}")
            removed = _enum_values(bs) - _enum_values(cprops[p])
            if removed:
                problems.append(f"{where}: {name}.{p} enum values removed {sorted(removed)}")
        for p in sorted(creq - breq):
            problems.append(f"{where}: {name}.{p} is now required" if p in bprops else f"{where}: {name}.{p} added as REQUIRED")
    return problems


def compare_docs(base: dict, cur: dict, where: str) -> list[str]:
    problems = []
    for path, ops in base.get("paths", {}).items():
        cur_ops = cur.get("paths", {}).get(path)
        if cur_ops is None:
            problems.append(f"{where}: path {path} removed")
            continue
        for method in ops:
            if method not in cur_ops:
                problems.append(f"{where}: {method.upper()} {path} removed")
    problems += compare_schemas(base.get("components", {}).get("schemas", {}),
                                cur.get("components", {}).get("schemas", {}), where)
    return problems


def main() -> int:
    if "--freeze" in sys.argv:
        BASELINE.mkdir(parents=True, exist_ok=True)
        for d in DOCS:
            shutil.copyfile(CURRENT / d, BASELINE / d)
        print(f"baseline frozen: {', '.join(DOCS)} -> {BASELINE.relative_to(ROOT)}")
        return 0
    problems = []
    for d in DOCS:
        if not (BASELINE / d).exists():
            print(f"no baseline for {d}: freeze one with --freeze (platform owner)")
            return 1
        problems += compare_docs(json.loads((BASELINE / d).read_text(encoding="utf-8")),
                                 json.loads((CURRENT / d).read_text(encoding="utf-8")), d)
    if problems:
        print("BREAKING CONTRACT CHANGES (v1 allows additive changes only; breaking changes need v2):")
        for p in problems:
            print("  -", p)
        return 1
    print("contract compatibility: OK (no breaking changes against the approved v1 baseline)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
