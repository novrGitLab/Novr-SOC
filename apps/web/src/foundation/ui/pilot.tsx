'use client';

// Shared building blocks for the pilot module pages: a typed data table, a labelled field, and an action runner
// that turns API errors into an honest message (never a silent failure).
import type { ReactNode } from 'react';
import { EmptyState } from '@/components/features/vms/kit';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import { ApiError, STATE_TEXT, uiState } from '@/foundation/api/errors';
import { ApiErrorState, LoadingState } from '@/foundation/ui/states';
import { inputCls } from '@/foundation/ui/sources';

export interface Column<T> { key: string; header: string; render: (row: T) => ReactNode; className?: string }

export function DataTable<T>({ rows, columns, rowKey, testid, empty = 'Nothing here yet.', caption }: {
    rows: T[]; columns: Column<T>[]; rowKey: (row: T) => string; testid?: string; empty?: string; caption?: string;
}) {
    if (rows.length === 0) return <EmptyState compact title={empty} />;
    return (
        <div className="overflow-x-auto">
            <table className="w-full text-sm" data-testid={testid}>
                {caption && <caption className="sr-only">{caption}</caption>}
                <thead className="bg-card-muted">
                    <tr className="text-left text-[11px] uppercase tracking-wider text-foreground-muted">
                        {columns.map((c) => <th key={c.key} scope="col" className={`px-3 py-2.5 font-semibold ${c.className ?? ''}`}>{c.header}</th>)}
                    </tr>
                </thead>
                <tbody className="divide-y divide-border">
                    {rows.map((r) => (
                        <tr key={rowKey(r)} data-row-id={rowKey(r)} className="hover:bg-card-muted/60 transition-colors">
                            {columns.map((c) => <td key={c.key} className={`px-3 py-2.5 align-top ${c.className ?? ''}`}>{c.render(r)}</td>)}
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

/** A section that loads one resource: loading, error and content states in one place. */
export function Loaded<T>({ title, hint, action, data, error, reload, children, testid }: {
    title: string; hint?: string; action?: ReactNode; data: T | undefined; error: unknown; reload?: () => void;
    children: (data: T) => ReactNode; testid?: string;
}) {
    return (
        <Card>
            <SectionTitle title={title} hint={hint} action={action} />
            <div className="mt-3" data-testid={testid}>
                {error ? <ApiErrorState error={error} onRetry={reload} /> : data === undefined ? <LoadingState label={`Loading ${title.toLowerCase()}`} /> : children(data)}
            </div>
        </Card>
    );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
    return <label className="text-xs text-foreground-muted flex flex-col gap-1 min-w-0">{label}{children}</label>;
}

export function TextInput(props: React.InputHTMLAttributes<HTMLInputElement>) {
    return <input {...props} className={`${inputCls} ${props.className ?? ''}`} />;
}

export function errorText(e: unknown): string {
    if (e instanceof ApiError && e.message) return e.message;
    return STATE_TEXT[uiState(e)].body;
}

export const fmt = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString('en-GB') : '—');
