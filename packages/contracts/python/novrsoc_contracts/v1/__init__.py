"""NovrSOC V2 shared contracts, version 1. Import modules explicitly, e.g.
`from novrsoc_contracts.v1 import platform, collector, soar, vms`."""
from . import (administration, ai_gateway, chat, collector, command, common, continuity, endpoints, governance, insights,  # noqa: F401
               inventory, nhai, operations, platform, portal, posture, protection, secops, soar, soc, sources, vms)
from .common import CONTRACT_VERSION  # noqa: F401

MODULES = {"common": common, "platform": platform, "collector": collector, "soar": soar, "vms": vms,
           "insights": insights, "nhai": nhai, "ai_gateway": ai_gateway, "protection": protection,
           "governance": governance, "operations": operations, "endpoints": endpoints, "soc": soc,
           # consolidation (additive)
           "inventory": inventory, "secops": secops, "posture": posture, "continuity": continuity, "chat": chat,
           "administration": administration, "command": command,
           # organization management (additive)
           "sources": sources,
           # organization portals and onboarding (additive)
           "portal": portal}
