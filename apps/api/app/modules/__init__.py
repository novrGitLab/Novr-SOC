"""Product modules, one sub-package per workstream module (Phase 3).

A workstream adds `app/modules/<name>/__init__.py` exporting:

    MODULE = ModuleInfo(name="vms", workstream="B", prefix="/api/v1/vms", summary="...")
    router = APIRouter(prefix="/api/v1/vms", tags=["vms"])

and the app mounts it automatically: no edit to app/main.py (a shared, platform-owned file) is needed.
Discovery is strict (fail closed at startup):
  * the package must export both MODULE and router;
  * MODULE.name must equal the package name, MODULE.prefix must be `/api/v1/<name>` and equal router.prefix;
  * every route must live under that prefix;
  * a module named in NOVRSOC_DISABLED_MODULES (comma separated) is not mounted.
Authorisation is checked separately for every mounted route (tests/test_platform_contracts.py): each one
must depend on a user session or a machine identity, unless it is in the reviewed public allowlist.
"""
from __future__ import annotations

import importlib
import os
import pkgutil
import re
from dataclasses import dataclass

from fastapi import APIRouter

_NAME = re.compile(r"^[a-z][a-z0-9_]{1,30}$")


@dataclass(frozen=True)
class ModuleInfo:
    name: str
    workstream: str          # "A".."G"
    prefix: str              # "/api/v1/<name>"
    summary: str


class ModuleError(RuntimeError):
    pass


def validate(pkg_name: str, info: object, router: object) -> tuple[ModuleInfo, APIRouter]:
    if not isinstance(info, ModuleInfo) or not isinstance(router, APIRouter):
        raise ModuleError(f"module {pkg_name}: must export MODULE (ModuleInfo) and router (APIRouter)")
    if not _NAME.match(info.name) or info.name != pkg_name:
        raise ModuleError(f"module {pkg_name}: MODULE.name must equal the package name")
    if info.workstream not in tuple("ABCDEFG"):
        raise ModuleError(f"module {pkg_name}: unknown workstream {info.workstream!r}")
    expected = f"/api/v1/{info.name.replace('_', '-')}"
    if info.prefix != expected or router.prefix != expected:
        raise ModuleError(f"module {pkg_name}: prefix must be {expected} on both MODULE and router")
    for route in router.routes:
        path = getattr(route, "path", "")
        if not (path == expected or path.startswith(expected + "/")):
            raise ModuleError(f"module {pkg_name}: route {path} is outside {expected}")
    return info, router


def discover() -> list[tuple[ModuleInfo, APIRouter]]:
    disabled = {m.strip() for m in os.environ.get("NOVRSOC_DISABLED_MODULES", "").split(",") if m.strip()}
    found = []
    for m in sorted(pkgutil.iter_modules(__path__), key=lambda m: m.name):
        if not m.ispkg or m.name.startswith("_") or m.name in disabled:
            continue
        mod = importlib.import_module(f"{__name__}.{m.name}")
        found.append(validate(m.name, getattr(mod, "MODULE", None), getattr(mod, "router", None)))
    return found
