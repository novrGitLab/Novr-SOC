"""Organization portal identity (PUBLIC: read before sign-in, by the request host).

Answers only what a sign-in page may show: whether this address is the platform or an organization's portal, and that
organization's name, display name, colors and logo. Nothing else about an organization is reachable without a session.
An unknown, disabled or archived portal, or a host outside the installation, answers 404.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy import text
from sqlalchemy.engine import Connection

from app import portal as portals
from app.core.config import Settings, get_settings
from app.core.errors import ApiError
from app.core.ratelimit import limited
from app.db.session import request_connection
from app.modules import ModuleInfo
from app.routers._responses import ERRORS
from novrsoc_contracts.v1.portal import PortalBranding, PortalInfo, PortalOrg, PortalTheme

MODULE = ModuleInfo(name="portal", workstream="E", prefix="/api/v1/portal",
                    summary="Organization portal identity and branding by host (public, read before sign-in)")
router = APIRouter(prefix="/api/v1/portal", tags=["portal"], responses=ERRORS)

_NOT_FOUND = ApiError(404, "portal_not_found", "There is no NovrSOC portal at this address")


@router.get("", response_model=PortalInfo, summary="Which portal this address is, with its public branding (no sign-in needed)",
            dependencies=[Depends(limited("portal"))])
def portal_info(request: Request, conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> PortalInfo:
    here = portals.resolve(conn, request, settings)
    if here.kind == "platform":
        return PortalInfo(kind="platform")
    if here.kind != "tenant":
        raise _NOT_FOUND
    primary = here.primary_color
    return PortalInfo(kind="tenant", organization=PortalOrg(slug=here.slug or "", name=here.name or ""),
                      branding=PortalBranding(display_name=here.display_name or here.name or "", primary_color=primary,
                                              secondary_color=here.secondary_color,
                                              text_on_primary=portals.text_on(primary) if primary else "#ffffff",
                                              logo_url=f"/api/v1/portal/logo?v={here.logo_sha256[:16]}" if here.logo_sha256 else None,
                                              theme=PortalTheme(**t) if (t := portals.theme_for(primary)) else None))


@router.get("/logo", summary="The organization's logo for this portal (PNG, JPEG or WebP; no sign-in needed)",
            response_class=Response, responses={200: {"content": {"image/png": {}, "image/jpeg": {}, "image/webp": {}}}},
            dependencies=[Depends(limited("portal"))])
def portal_logo(request: Request, conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> Response:
    host = portals.request_host(request, settings)
    kind, label = portals.classify(host, settings)
    if kind != "tenant":
        raise _NOT_FOUND
    r = conn.execute(text("SELECT * FROM novrsoc.portal_logo(:l)"), {"l": label}).first()
    if r is None:
        raise _NOT_FOUND
    return Response(bytes(r.logo), media_type=r.logo_type,
                    headers={"Cache-Control": "public, max-age=300", "ETag": f'"{r.logo_sha256}"', "X-Content-Type-Options": "nosniff",
                             "Content-Security-Policy": "default-src 'none'; sandbox"})
