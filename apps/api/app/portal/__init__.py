"""Organization portals: hostname-based tenant routing for ONE shared deployment.

The request host only SELECTS which organization's branding a page shows and RESTRICTS who may sign in there; it never
grants access. Rules (tests/modules/portal):
  * platform host (Settings.platform_hosts): the central platform. Staff sign in here; the Command Center lives here.
  * <label>.<portal_base_domain>: the portal of the ONE active client organization whose enabled portal is <label>.
    Only that organization's home members may sign in there.
  * anything else (another domain, a nested label, a disabled or unknown portal, a malformed Host): no portal; sign-in
    and sessions are refused.
  * a session is bound to the host it was created on (sessions.portal_org_id). Presented on any other host it is
    refused (401) and audited, so a stolen cookie or a forged Host header never moves a session to another tenant.
    Cookies are host-only (no Domain attribute), so browsers never send one portal's cookie to another.
The host comes from Host, or from X-Forwarded-Host only when Settings.trust_forwarded_host (development proxy).
"""
from __future__ import annotations

import base64
import hashlib
import re
import secrets
import uuid
from dataclasses import dataclass
from typing import Literal

from fastapi import Request
from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.core.config import Settings
from app.core.errors import ApiError

HOST = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$")
RESERVED = frozenset({"www", "api", "app", "admin", "platform", "soc", "mail", "smtp", "imap", "pop", "ftp", "vpn", "status", "docs",
                      "static", "assets", "cdn", "login", "auth", "install", "portal", "novrsoc", "localhost"})


@dataclass(frozen=True)
class Portal:
    kind: Literal["platform", "tenant", "unknown"]
    host: str
    label: str | None = None
    org_id: uuid.UUID | None = None
    slug: str | None = None
    name: str | None = None
    display_name: str | None = None
    primary_color: str | None = None
    secondary_color: str | None = None
    logo_sha256: str | None = None


def request_host(request: Request, settings: Settings) -> str:
    """The host the browser addressed, lower case, without port or trailing dot ('' when unusable)."""
    raw = ""
    if settings.trust_forwarded_host:
        raw = request.headers.get("x-forwarded-host", "")
    raw = (raw or request.headers.get("host", "")).split(",")[0].strip().lower()
    if raw.startswith("["):                                  # IPv6 literal: never a portal
        return raw
    if raw.count(":") == 1:
        raw, _, port = raw.partition(":")
        if not port.isdigit():
            return ""
    return raw.rstrip(".")


def classify(host: str, settings: Settings) -> tuple[Literal["platform", "tenant", "unknown"], str | None]:
    if host in settings.platform_host_set:
        return "platform", None
    if not HOST.match(host):
        return "unknown", None
    base = settings.portal_base_domain
    if base and host.endswith("." + base):
        label = host[: -len(base) - 1]
        if LABEL.match(label) and label not in RESERVED:     # exactly one label: a.b.<base> is not a portal
            return "tenant", label
    return "unknown", None


def resolve(conn: Connection, request: Request, settings: Settings) -> Portal:
    host = request_host(request, settings)
    kind, label = classify(host, settings)
    if kind != "tenant":
        return Portal(kind, host)
    r = conn.execute(text("SELECT * FROM novrsoc.portal_for_host(:l)"), {"l": label}).first()
    if r is None:
        return Portal("unknown", host, label)
    return Portal("tenant", host, label, r.org_id, r.slug, r.name, r.display_name or r.name, r.primary_color, r.secondary_color,
                  r.logo_sha256)


def portal_of(request: Request) -> Portal | None:
    return getattr(request.state, "portal", None)


# ---------------------------------------------------------------- links handed to people
def base_url(settings: Settings, subdomain: str | None, portal_enabled: bool) -> str:
    """https://<subdomain>.<base> for an organization with an enabled portal, else the platform host."""
    if subdomain and portal_enabled and settings.portal_base_domain:
        host = f"{subdomain}.{settings.portal_base_domain}"
    else:
        host = settings.public_platform_host or sorted(settings.platform_host_set)[0]
    default = 443 if settings.public_scheme == "https" else 80
    port = f":{settings.public_port}" if settings.public_port and settings.public_port != default else ""
    return f"{settings.public_scheme}://{host}{port}"


# ---------------------------------------------------------------- branding
LOGO_TYPES = {"image/png": (b"\x89PNG\r\n\x1a\n",), "image/jpeg": (b"\xff\xd8\xff",), "image/webp": (b"RIFF",)}
LOGO_MAX = 256 * 1024
COLOR = re.compile(r"^#[0-9a-f]{6}$")


def check_logo(content_type: str, data_b64: str) -> tuple[bytes, str]:
    """(bytes, sha256). Raster only (SVG can carry script); the bytes must BE the declared format."""
    if content_type not in LOGO_TYPES:
        raise ApiError(422, "logo_type_not_allowed", "A logo must be PNG, JPEG or WebP (SVG is not accepted)")
    try:
        data = base64.b64decode(data_b64, validate=True)
    except (ValueError, TypeError):
        raise ApiError(422, "validation_error", "The logo is not valid base64") from None
    if not data or len(data) > LOGO_MAX:
        raise ApiError(422, "logo_too_large", f"A logo must be at most {LOGO_MAX // 1024} KiB")
    if not any(data.startswith(m) for m in LOGO_TYPES[content_type]) or (content_type == "image/webp" and data[8:12] != b"WEBP"):
        raise ApiError(422, "logo_content_mismatch", f"The file is not a {content_type.split('/')[1].upper()} image")
    return data, hashlib.sha256(data).hexdigest()


def luminance(hex_color: str) -> float:
    def ch(c: float) -> float:
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5))
    return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)


def contrast(a: str, b: str) -> float:
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return round((la + 0.05) / (lb + 0.05), 2)


def text_on(hex_color: str) -> str:
    """White or near-black text, whichever reads better on the color (WCAG contrast)."""
    return "#ffffff" if contrast(hex_color, "#ffffff") >= contrast(hex_color, "#111827") else "#111827"



def mix(a: str, b: str, weight_b: float) -> str:
    """a mixed with b (weight_b of b), as #rrggbb."""
    ca = [int(a[i:i + 2], 16) for i in (1, 3, 5)]
    cb = [int(b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * weight_b):02x}" for x, y in zip(ca, cb))


THEME_MIN_CONTRAST = 4.5   # the primary color carries white text (buttons) and is used as text on light surfaces


def theme_for(primary: str | None) -> dict | None:
    """The portal theme derived from an organization's primary color, or None when the color is not APPROVED: it must
    reach WCAG AA (4.5:1) against white, because the interface puts white text on it and uses it as text on white.
    Hover, fill and tints are derived, so every state keeps the same contrast relationships as the NovrSOC theme."""
    if not primary or not COLOR.match(primary) or contrast(primary, "#ffffff") < THEME_MIN_CONTRAST:
        return None
    return {"primary": primary, "primary_hover": mix(primary, "#000000", 0.18), "primary_fill": mix(primary, "#ffffff", 0.12),
            "tint_light": mix(primary, "#ffffff", 0.92), "tint_dark": mix(primary, "#0b0b12", 0.78), "on_primary": "#ffffff"}


# ---------------------------------------------------------------- agent / manager version compatibility
SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def agent_compatibility(manager_version: str | None, configured: str) -> tuple[str | None, str]:
    """(agent version to install, '') when compatible, else (None, reason). NovrSIEM agents must share the manager's
    major version and must not be NEWER than the manager. With no configured version, the agent matches the manager."""
    if not manager_version:
        return None, "The NovrSIEM manager version is unknown, so no agent version can be chosen safely."
    m = SEMVER.match(manager_version)
    if not m:
        return None, f"The NovrSIEM manager reported an unrecognized version ({manager_version[:40]})."
    mv = tuple(int(x) for x in m.groups())
    if not configured:
        return ".".join(map(str, mv)), ""
    c = SEMVER.match(configured)
    if not c:
        return None, "The configured agent version is not a version number."
    cv = tuple(int(x) for x in c.groups())
    if cv[0] != mv[0]:
        return None, f"Agent {configured} and manager {'.'.join(map(str, mv))} have different major versions."
    if cv > mv:
        return None, f"Agent {configured} is newer than the manager {'.'.join(map(str, mv))}: agents must not be newer than the manager."
    return configured, ""


# ---------------------------------------------------------------- NovrAgent installer (server-controlled enrollment)
OS_SCRIPT = {"linux": "sh", "macos": "sh", "windows": "ps1"}
SAFE_VALUE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
TICKET = re.compile(r"^[A-Za-z0-9_-]{30,80}$")
HOSTNAME = re.compile(r"[^A-Za-z0-9._-]")


def _safe(v: str) -> str:
    if not SAFE_VALUE.match(v):
        raise ApiError(409, "installer_unavailable", "An installer value is not safe to embed")
    return v


def agent_name(slug: str, hostname: str) -> str:
    """The agent's name on the manager: the organization's identifier and the endpoint's own name (sanitized)."""
    host = HOSTNAME.sub("", hostname)[:64].strip("-.") or "endpoint"
    return f"{slug[:40]}-{host}"[:128]


def install_script(os_name: str, *, org_name: str, manager: str, port: int, version: str, enroll_url: str, ticket: str,
                   expires: str) -> str:
    """The generated installer. It installs the agent package (publisher signature verified first) WITHOUT any
    enrollment password or group, then asks NovrSOC to register this endpoint with the organization-bound ticket and
    imports the agent key NovrSOC returns. The manager never accepts self-enrollment, so the ticket is the only way in."""
    m, v = _safe(manager), _safe(version)
    if not TICKET.match(ticket) or not enroll_url.startswith(("https://", "http://")) or "'" in enroll_url or '"' in enroll_url:
        raise ApiError(409, "installer_unavailable", "An installer value is not safe to embed")
    major = v.split(".")[0] + ".x"
    org = re.sub(r"[^A-Za-z0-9 ._-]", "", org_name)[:80]
    if os_name == "windows":
        return f"""# NovrAgent installer for {org}. Generated by NovrSOC; valid until {expires}. Delete this file after use.
# Run in an elevated PowerShell. NovrSOC registers this endpoint for the organization; no password is used or stored.
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{
    throw 'Run this installer in an elevated (Administrator) PowerShell.' }}
$Manager = '{m}'; $Port = '{port}'; $Version = '{v}'; $EnrollUrl = '{enroll_url}'; $Ticket = '{ticket}'
$Msi = Join-Path $env:TEMP "novragent-$Version.msi"
Invoke-WebRequest -UseBasicParsing "https://packages.wazuh.com/{major}/windows/wazuh-agent-$Version-1.msi" -OutFile $Msi
$Sig = Get-AuthenticodeSignature $Msi
if ($Sig.Status -ne 'Valid' -or $Sig.SignerCertificate.Subject -notmatch 'Wazuh') {{ Remove-Item $Msi; throw 'The agent package signature is not valid: not installed.' }}
$P = Start-Process msiexec.exe -ArgumentList @('/i', $Msi, '/qn', "WAZUH_MANAGER=$Manager", "WAZUH_MANAGER_PORT=$Port") -Wait -PassThru
Remove-Item $Msi
if ($P.ExitCode -ne 0) {{ throw "The agent installation failed (msiexec $($P.ExitCode))." }}
$Name = ($env:COMPUTERNAME -replace '[^A-Za-z0-9._-]', '')
if ($Name.Length -gt 64) {{ $Name = $Name.Substring(0, 64) }}
$Body = @{{ ticket = $Ticket; hostname = $Name; os = 'windows' }} | ConvertTo-Json -Compress
$Resp = Invoke-RestMethod -Method Post -Uri $EnrollUrl -ContentType 'application/json' -Body $Body
if (-not $Resp.key) {{ throw 'NovrSOC did not enroll this endpoint.' }}
$Bin = Join-Path ${{env:ProgramFiles(x86)}} 'ossec-agent\\manage_agents.exe'
'y' | & $Bin -i $Resp.key | Out-Null
Start-Service WazuhSvc
Remove-Item -LiteralPath $PSCommandPath -ErrorAction SilentlyContinue
Write-Host "NovrAgent installed as $($Resp.name). It appears in your NovrSOC portal within a few minutes."
"""
    return f"""#!/bin/sh
# NovrAgent installer for {org} (Linux and macOS). Generated by NovrSOC; valid until {expires}. Delete this file after use.
# Run as root. NovrSOC registers this endpoint for the organization; no password is used or stored.
set -eu
umask 077
MANAGER='{m}'; PORT='{port}'; VERSION='{v}'; ENROLL_URL='{enroll_url}'; TICKET='{ticket}'
[ "$(id -u)" -eq 0 ] || {{ echo 'Run this installer as root (sudo sh novragent.sh).' >&2; exit 1; }}
export WAZUH_MANAGER="$MANAGER" WAZUH_MANAGER_PORT="$PORT"
case "$(uname -s)" in
  Linux)
    BIN=/var/ossec/bin
    if command -v apt-get >/dev/null 2>&1; then
      curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor > /usr/share/keyrings/novragent.gpg
      echo 'deb [signed-by=/usr/share/keyrings/novragent.gpg] https://packages.wazuh.com/{major}/apt/ stable main' > /etc/apt/sources.list.d/novragent.list
      apt-get update -q && apt-get install -y "wazuh-agent=$VERSION-1"
    elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
      rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
      printf '[novragent]\\nname=NovrAgent\\nbaseurl=https://packages.wazuh.com/{major}/yum/\\ngpgcheck=1\\nenabled=1\\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\\n' > /etc/yum.repos.d/novragent.repo
      if command -v dnf >/dev/null 2>&1; then dnf install -y "wazuh-agent-$VERSION-1"; else yum install -y "wazuh-agent-$VERSION-1"; fi
    else
      echo 'Unsupported Linux distribution: ask your NovrSOC administrator for a package.' >&2; exit 1
    fi ;;
  Darwin)
    BIN=/Library/Ossec/bin
    ARCH=$(uname -m); [ "$ARCH" = arm64 ] || ARCH=intel64
    PKG="/tmp/novragent-$VERSION.pkg"
    curl -fsSLo "$PKG" "https://packages.wazuh.com/{major}/macos/wazuh-agent-$VERSION-1.$ARCH.pkg"
    pkgutil --check-signature "$PKG" | grep -q 'Developer ID Installer: Wazuh' || {{ rm -f "$PKG"; echo 'The agent package signature is not valid: not installed.' >&2; exit 1; }}
    echo "WAZUH_MANAGER='$MANAGER'" > /tmp/wazuh_envs
    installer -pkg "$PKG" -target /; rm -f "$PKG" /tmp/wazuh_envs ;;
  *) echo 'Unsupported operating system.' >&2; exit 1 ;;
esac
NAME=$(hostname | tr -cd 'A-Za-z0-9._-' | cut -c1-64)
RESP=$(curl -fsS -X POST "$ENROLL_URL" -H 'Content-Type: application/json' --data "{{\\"ticket\\":\\"$TICKET\\",\\"hostname\\":\\"$NAME\\",\\"os\\":\\"{os_name}\\"}}")
KEY=$(printf '%s' "$RESP" | sed -n 's/.*"key":"\\([A-Za-z0-9+\\/=]*\\)".*/\\1/p')
[ -n "$KEY" ] || {{ echo 'NovrSOC did not enroll this endpoint.' >&2; exit 1; }}
printf 'y\\n' | "$BIN/manage_agents" -i "$KEY" >/dev/null
if [ "$(uname -s)" = Linux ]; then systemctl daemon-reload && systemctl enable --now wazuh-agent; else "$BIN/wazuh-control" start; fi
rm -f -- "$0"
echo 'NovrAgent installed. It appears in your NovrSOC portal within a few minutes.'
"""


def provisioned_group_name(slug: str) -> str:
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    return f"nv-{slug[:24].strip('-')}-{''.join(secrets.choice(alphabet) for _ in range(8))}"
