"""CVE intelligence, merged per CVE across its snapshots (every import is kept as a snapshot row).

For each field the most recent NON-EMPTY value wins, so a later CVSS-only import never hides an earlier KEV listing:
KEV is true when any recorded source lists the CVE as known exploited. `snaps` counts the snapshots behind the view.
"""
from __future__ import annotations

_MERGED = """SELECT cve_id,
       (array_agg(cvss_v3 ORDER BY captured_at DESC) FILTER (WHERE cvss_v3 IS NOT NULL))[1] AS cvss_v3,
       (array_agg(cvss_vector ORDER BY captured_at DESC) FILTER (WHERE cvss_vector IS NOT NULL))[1] AS cvss_vector,
       (array_agg(epss ORDER BY captured_at DESC) FILTER (WHERE epss IS NOT NULL))[1] AS epss,
       bool_or(kev) AS kev, max(kev_added) AS kev_added, max(published_at) AS published_at,
       coalesce((array_agg(description ORDER BY captured_at DESC) FILTER (WHERE description <> ''))[1], '') AS description,
       (array_agg(source ORDER BY captured_at DESC))[1] AS source, max(captured_at) AS captured_at, count(*) AS snaps
       FROM novrsoc.ti_cve_records {where} GROUP BY cve_id"""


def merged(where: str = "") -> str:
    """A sub-select of merged CVE records; `where` filters the snapshot rows (e.g. "WHERE cve_id = ANY(:c)")."""
    return _MERGED.format(where=where)
