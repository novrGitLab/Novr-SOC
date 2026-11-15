'use client';

import { KeyRound } from 'lucide-react';
import { PageHeader } from '@/components/features/vms/kit';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import { PasswordChangeForm } from '@/foundation/session/PasswordChange';
import { useSession } from '@/foundation/session/SessionProvider';

export default function AccountPage() {
    const { session } = useSession();
    return (
        <>
            <PageHeader title="Account" icon={KeyRound} description="Your sign-in identity and password. Roles and organization access are managed by a platform administrator." />
            <Card>
                <SectionTitle title="Signed in as" />
                <dl className="mt-3 grid grid-cols-1 sm:grid-cols-[10rem_1fr] gap-x-4 gap-y-2 text-sm" data-testid="account-identity">
                    <dt className="text-foreground-muted">Email</dt><dd className="break-all">{session.user.email}</dd>
                    <dt className="text-foreground-muted">Role</dt><dd>{session.role.replace('_', ' ')}</dd>
                    <dt className="text-foreground-muted">Home organization</dt><dd>{session.home_org.name}</dd>
                </dl>
            </Card>
            <PasswordChangeForm />
        </>
    );
}
