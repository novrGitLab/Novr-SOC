"""Generate (or --check) the published contract documents.

  packages/contracts/openapi/novrsoc-api.v1.json        OpenAPI of the running FastAPI app (HTTP API)
  packages/contracts/openapi/novrsoc-contracts.v1.json  OpenAPI document whose components are ALL shared
                                                        v1 models (machine, internal and API contracts);
                                                        used to generate TypeScript types
  packages/contracts/schemas/v1/<module>.schema.json    JSON Schema (2020-12) per contract module

Both OpenAPI documents are validated with openapi-spec-validator. --check exits 1 if any committed file
differs from what the code generates (contract drift). Run with the API virtualenv:
  apps/api/.venv/Scripts/python scripts/contracts/export.py [--check]
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from openapi_spec_validator import validate  # noqa: E402
from pydantic import BaseModel  # noqa: E402
from pydantic.json_schema import models_json_schema  # noqa: E402

from novrsoc_contracts import v1  # noqa: E402
from novrsoc_contracts.v1 import common  # noqa: E402

OUT_API = ROOT / "packages" / "contracts" / "openapi" / "novrsoc-api.v1.json"
OUT_CONTRACTS = ROOT / "packages" / "contracts" / "openapi" / "novrsoc-contracts.v1.json"
OUT_SCHEMAS = ROOT / "packages" / "contracts" / "schemas" / "v1"
ABSTRACT = {common.Contract, common.MachineInbound, common.MachineOutbound, common.Internal, common.Page}


def dump(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def concrete_models(module) -> list[type[BaseModel]]:
    return [v for v in vars(module).values()
            if isinstance(v, type) and issubclass(v, BaseModel) and v.__module__ == module.__name__ and v not in ABSTRACT]


def api_openapi() -> dict:
    os.environ.setdefault("NOVRSOC_ENV", "test")
    from app.core.config import Settings
    from app.main import create_app
    settings = Settings(_env_file=None, env="test", database_url="postgresql+psycopg://u:p@127.0.0.1:1/openapi-export",  # type: ignore[call-arg]
                        session_cookie_secure=False)
    doc = create_app(settings).openapi()
    doc["info"]["x-contract-version"] = v1.CONTRACT_VERSION
    return doc


def contracts_openapi() -> dict:
    models = [m for mod in v1.MODULES.values() for m in concrete_models(mod)]
    _, defs = models_json_schema([(m, "validation") for m in models], ref_template="#/components/schemas/{model}")
    schemas = defs.get("$defs", {})
    for m in models:
        if m.__name__ in schemas:
            schemas[m.__name__]["x-novrsoc-direction"] = m.direction.value
            schemas[m.__name__]["x-novrsoc-module"] = m.__module__.rsplit(".", 1)[-1]
    return {"openapi": "3.1.0",
            "info": {"title": "NovrSOC shared contracts", "version": v1.CONTRACT_VERSION,
                     "description": "Every v1 contract model. Not an HTTP API: paths is empty by design."},
            "paths": {}, "components": {"schemas": schemas}}


def module_schemas() -> dict[str, dict]:
    out = {}
    for name, mod in v1.MODULES.items():
        models = concrete_models(mod)
        if not models:
            continue
        _, defs = models_json_schema([(m, "validation") for m in models], ref_template="#/$defs/{model}")
        out[name] = {"$schema": "https://json-schema.org/draft/2020-12/schema",
                     "$id": f"https://contracts.novrsoc.invalid/v1/{name}.schema.json",
                     "title": f"NovrSOC contracts v1: {name}", "version": v1.CONTRACT_VERSION, **defs}
    return out


def main() -> int:
    check = "--check" in sys.argv
    files: dict[Path, str] = {}
    api, contracts = api_openapi(), contracts_openapi()
    validate(api)
    validate(contracts)
    files[OUT_API] = dump(api)
    files[OUT_CONTRACTS] = dump(contracts)
    for name, doc in module_schemas().items():
        files[OUT_SCHEMAS / f"{name}.schema.json"] = dump(doc)
    drift = []
    for path, content in files.items():
        if check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                drift.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
    n_paths = len(api.get("paths", {}))
    n_models = len(contracts["components"]["schemas"])
    if check:
        if drift:
            print("CONTRACT DRIFT:", *drift, sep="\n  ")
            return 1
        print(f"contracts up to date: {n_paths} API paths, {n_models} contract schemas, both OpenAPI documents valid")
        return 0
    print(f"wrote {len(files)} files: {n_paths} API paths, {n_models} contract schemas; OpenAPI documents valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
