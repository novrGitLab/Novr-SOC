'use client';

import { Card, SectionTitle } from '@/components/features/vms/ui';

export const rows = (t: { period_start: string; values: Record<string, number> }[]) => t.map((p) => ({ day: p.period_start, ...p.values }));

export function ScoreCard({ score }: { score: { score?: number | null; state: string; coverage_percent: number; method: string; excluded?: string[] } }) {
    return (
        <Card>
            <SectionTitle title="Security posture score" hint="Explainable: open Security posture for every measurement" />
            <div className="mt-3 flex items-end gap-4" data-testid="posture-score" data-state={score.state}>
                <p className="text-5xl font-black tabular-nums">{score.score ?? '—'}</p>
                <div className="text-xs text-foreground-muted pb-1">
                    {score.state === 'ok' ? <p>Out of 100, from measurements covering {score.coverage_percent}% of the weight.</p>
                        : <p className="font-semibold text-foreground">Withheld: the available measurements cover only {score.coverage_percent}% of the weight.</p>}
                    {score.excluded?.length ? <p className="mt-1">Not scored (no data or not permitted): {score.excluded.join(', ').replace(/_/g, ' ')}</p> : null}
                </div>
            </div>
            <p className="mt-3 text-[11px] text-foreground-muted">{score.method}</p>
        </Card>
    );
}

