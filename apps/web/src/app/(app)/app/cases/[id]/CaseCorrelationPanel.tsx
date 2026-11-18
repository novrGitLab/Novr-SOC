'use client';

// SIEM and VMS evidence of one case, joined through the canonical asset inventory: each asset of the case's alerts with
// its open vulnerability findings. The API decides what may be shown (findings need vms:read); nothing is inferred here.
import Link from 'next/link';
import { useCallback } from 'react';
import { SeverityBadge, Tag } from '@/components/features/vms/kit';
import { useSession } from '@/foundation/session/SessionProvider';
import { Loaded } from '@/foundation/ui/pilot';
import { useResource } from '@/foundation/ui/useResource';
import { socApi } from '../../alerts/api';

export function CaseCorrelationPanel({ caseId }: { caseId: string }) {
    const { orgId } = useSession();
    const r = useResource(useCallback(() => socApi.caseCorrelation(orgId, caseId), [orgId, caseId]));
    return (
        <Loaded title="Assets and vulnerabilities" hint="The assets of this case's alerts, with their open vulnerability findings"
            data={r.data} error={r.error} reload={r.reload} testid="case-correlation">
            {(d) => (
                <div className="space-y-3 text-sm min-w-0">
                    {d.assets.length === 0 && <p className="text-xs text-foreground-muted">No alert of this case is attributed to an inventory asset yet.</p>}
                    {d.assets.map((a) => (
                        <div key={a.asset_id} className="border border-border rounded-xl p-3 min-w-0" data-asset={a.display_name}>
                            <p className="flex flex-wrap items-center gap-2">
                                <Link href={`/app/assets/${a.asset_id}`} className="font-semibold text-purple hover:underline wrap-any">{a.display_name}</Link>
                                <Tag>criticality {a.criticality}</Tag><Tag>{a.exposure.replace(/_/g, ' ')}</Tag>
                                <span className="text-[11px] text-foreground-muted">{a.alert_ids.length} alert(s) in this case</span>
                            </p>
                            {d.findings_visible && (a.open_findings.length === 0
                                ? <p className="mt-2 text-xs text-foreground-muted">No open vulnerability finding is recorded for this asset (this does not mean it was scanned).</p>
                                : (
                                    <ul className="mt-2 divide-y divide-border" data-testid="case-findings">
                                        {a.open_findings.map((f) => (
                                            <li key={f.id} className="py-1.5 flex flex-wrap items-start gap-2 min-w-0">
                                                <SeverityBadge severity={f.severity} />
                                                <Link href={`/app/vms/findings?finding=${f.id}`} className="flex-1 basis-[12rem] wrap-any hover:underline">{f.title}</Link>
                                                <span className="text-[11px] text-foreground-muted wrap-any">{f.priority} · risk {f.risk_score}{f.port ? ` · port ${f.port}` : ''}
                                                    {f.cves.length > 0 && ` · ${f.cves.slice(0, 3).join(', ')}${f.cves.length > 3 ? '…' : ''}`} · {f.status.replace(/_/g, ' ')}</span>
                                            </li>
                                        ))}
                                        {a.open_findings_total > a.open_findings.length && (
                                            <li className="py-1.5 text-[11px]"><Link href={`/app/assets/${a.asset_id}`} className="underline">
                                                {a.open_findings_total - a.open_findings.length} more open finding(s) on this asset</Link></li>
                                        )}
                                    </ul>
                                ))}
                        </div>
                    ))}
                    {!d.findings_visible && <p className="text-xs text-foreground-muted">Vulnerability findings are not shown: your role cannot read them.</p>}
                    {d.alerts_without_asset > 0 && <p className="text-xs text-foreground-muted">{d.alerts_without_asset} linked alert(s) are not yet attributed to an inventory asset.</p>}
                </div>
            )}
        </Loaded>
    );
}
