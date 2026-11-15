'use client';

// NHAI inside a workflow (VMS finding, asset): request an evidence-grounded draft, poll while the worker runs it, and
// show the validated result for human review. A draft never changes a record and never triggers an action.
import { useEffect, useState } from 'react';
import { Sparkles } from 'lucide-react';
import { btn } from '@/components/features/vms/kit';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { useSession } from '@/foundation/session/SessionProvider';
import { useAction } from '@/foundation/ui/module';
import { NhaiResult } from './AlertIntelPanel';
import { nhaiApi } from './api';

type Job = Schemas['NhaiJob'];

export function NhaiSubjectPanel({ title, initial, request, testid }: {
    title: string; initial?: Job | null; request: () => Promise<Job>; testid?: string;
}) {
    const { orgId, can } = useSession();
    const [job, setJob] = useState<Job | null>(initial ?? null);
    const act = useAction();
    const running = job && (job.status === 'queued' || job.status === 'running');
    useEffect(() => {
        if (!running || !job) return;
        const t = setInterval(() => { void nhaiApi.job(orgId, job.id).then(setJob).catch(() => undefined); }, 5000);
        return () => clearInterval(t);
    }, [running, job, orgId]);
    return (
        <Card>
            <SectionTitle title={title} hint="Novr Human-Assisted Intelligence: a validated draft that cites its evidence, for human review" />
            <div className="mt-3 space-y-3" data-testid={testid}>
                {job ? <NhaiResult job={job} onChange={setJob} /> : <p className="text-xs text-foreground-muted">No analysis has been requested yet.</p>}
                {can('nhai:analyze') && !running && (
                    <button className={btn('secondary')} disabled={act.busy} onClick={() => void act.run(request).then((j) => j && setJob(j))}>
                        <Sparkles className="w-3.5 h-3.5" aria-hidden /> {job ? 'Request a new analysis' : 'Request an NHAI analysis'}</button>
                )}
                {act.notice}
            </div>
        </Card>
    );
}
