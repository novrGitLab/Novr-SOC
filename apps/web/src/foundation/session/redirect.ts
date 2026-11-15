/** Only same-app relative paths under /app are honoured as a post-login destination (no open redirect). */
export function safeNext(next: string | null | undefined): string {
    if (!next || !next.startsWith('/app') || next.startsWith('//') || next.includes('\\')) return '/app';
    return next === '/app' || next.startsWith('/app/') || next.startsWith('/app?') ? next : '/app';
}
