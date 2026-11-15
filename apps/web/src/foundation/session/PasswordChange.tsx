'use client';

// Password change form. Shown in place of every page while the account still has a temporary password (the API
// refuses other routes with 403 password_change_required), and on /app/account for a voluntary change.
import { useState } from 'react';
import { Notice, btn, type Msg } from '@/components/features/vms/kit';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import { api } from '@/foundation/api/client';
import { useSession } from '@/foundation/session/SessionProvider';
import { Field, TextInput, errorText } from '@/foundation/ui/pilot';

export function PasswordChangeForm({ required = false }: { required?: boolean }) {
    const { refresh } = useSession();
    const [current, setCurrent] = useState('');
    const [next, setNext] = useState('');
    const [again, setAgain] = useState('');
    const [busy, setBusy] = useState(false);
    const [msg, setMsg] = useState<Msg>(null);
    const bytes = new TextEncoder().encode(next).length;
    const problem = next.length > 0 && next.length < 12 ? 'At least 12 characters.'
        : bytes > 72 ? 'At most 72 bytes.'
        : again.length > 0 && again !== next ? 'The two new passwords differ.'
        : next.length > 0 && next === current ? 'Choose a password that differs from the current one.' : null;
    const ready = current.length > 0 && next.length >= 12 && bytes <= 72 && again === next && next !== current;

    const submit = async () => {
        setBusy(true); setMsg(null);
        try {
            await api.changePassword({ current_password: current, new_password: next });
            setCurrent(''); setNext(''); setAgain('');
            setMsg({ ok: true, text: 'Password changed. Your other sessions were signed out.' });
            if (required) refresh();
        } catch (e) {
            setMsg({ ok: false, text: errorText(e) });
        } finally { setBusy(false); }
    };

    return (
        <Card>
            <SectionTitle title={required ? 'Set your own password' : 'Change password'}
                hint={required ? 'Your account was created with a temporary password. Choose your own before continuing; nothing else is available until then.'
                    : 'Changing it signs out your other sessions.'} />
            <form className="mt-3 grid gap-3 max-w-md" data-testid="password-change"
                onSubmit={(e) => { e.preventDefault(); if (ready && !busy) void submit(); }}>
                <Field label="Current password">
                    <TextInput type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} data-testid="pw-current" />
                </Field>
                <Field label="New password (12 or more characters)">
                    <TextInput type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} data-testid="pw-new" />
                </Field>
                <Field label="New password again">
                    <TextInput type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} data-testid="pw-again" />
                </Field>
                {problem && <p className="text-xs text-red" role="status">{problem}</p>}
                <div><button type="submit" className={btn('primary')} disabled={!ready || busy} data-testid="pw-submit">{busy ? 'Saving…' : 'Change password'}</button></div>
                <Notice msg={msg} />
            </form>
        </Card>
    );
}
