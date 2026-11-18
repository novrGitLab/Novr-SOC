'use client';

// V2 application shell. Visual direction: the NCC IT demo layout (fixed 260px sidebar, sectioned
// navigation, purple active state, user card, sticky header, off-canvas navigation on small screens),
// in NovrSOC branding (the canonical brand purple token, --brand-purple) and design tokens. Behaviour stays honest: modules that are not built
// are labelled, never linked, and no status indicator is shown that the API does not back.
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import {
    Activity, ArrowRightLeft, BarChart3, Bell, Boxes, Briefcase, Bug, Building2, ChevronDown, ClipboardCheck, ClipboardList, CreditCard, Database,
    Download, FileBarChart, Fingerprint, Gauge, Globe2, HeartPulse, KeyRound, LayoutDashboard, LifeBuoy, LogOut, Mail, MapPin, Menu, MessageSquare, Monitor,
    Moon, Landmark, Network, Radar, ScanSearch, ScrollText, ShieldAlert, ShieldCheck, Sparkles, Sun, Target, Timer, UserCog, Workflow,
    Wrench, X, Zap, type LucideIcon,
} from 'lucide-react';
import { secopsApi } from '@/foundation/api/modules';
import { useResource } from '@/foundation/ui/useResource';
import { Logo } from '@/components/shared/Logo';
import { useTheme } from '@/components/providers/ThemeProvider';
import { FOUNDATION_NAV, isActive, visibleNav, type NavIcon, type NavItem } from '@/foundation/navigation';
import { PasswordChangeForm } from '@/foundation/session/PasswordChange';
import { useSession } from '@/foundation/session/SessionProvider';

const ICONS: Record<NavIcon, LucideIcon> = {
    overview: LayoutDashboard, posture: Gauge, reports: FileBarChart, alerts: Bell, cases: Briefcase, playbooks: Workflow, soar: Zap,
    handover: ArrowRightLeft, sla: Timer, vms: ShieldAlert, surface: Network, findings: Bug, scans: ScanSearch, risk: Target, remediation: Wrench,
    vmsreport: ClipboardCheck, insights: Radar, actors: Fingerprint, cves: Database, nhai: Sparkles, cnii: Landmark, email: Mail, brand: ShieldCheck,
    assets: Boxes, chat: MessageSquare, recovery: LifeBuoy, admin: Building2, users: UserCog, billing: CreditCard, analytics: BarChart3,
    exports: Download, wazuh: Activity, health: HeartPulse, audit: ScrollText, sites: MapPin, endpoints: Monitor, collectors: ClipboardList, command: Globe2, policy: ShieldCheck,
};

function NotificationsBell() {
    const { orgId } = useSession();
    const [open, setOpen] = useState(false);
    const [tick, setTick] = useState(0);
    const res = useResource(useCallback(() => secopsApi.notifications(orgId), [orgId, tick])); // eslint-disable-line react-hooks/exhaustive-deps
    useEffect(() => { const t = setInterval(() => setTick((x) => x + 1), 60_000); return () => clearInterval(t); }, []);
    const unread = res.data?.unread ?? 0;
    return (
        <div className="relative">
            <button type="button" onClick={() => setOpen((v) => !v)} aria-label={`Notifications${unread ? `, ${unread} unread` : ''}`} aria-expanded={open}
                data-testid="notifications" className="relative p-2 rounded-lg text-foreground-muted hover:text-foreground hover:bg-card-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-purple/60">
                <Bell className="w-4 h-4" aria-hidden />
                {unread > 0 && <span className="absolute -top-0.5 -right-0.5 min-w-4 h-4 px-1 rounded-full bg-red text-white text-[10px] font-bold leading-4 text-center">{unread > 99 ? '99+' : unread}</span>}
            </button>
            {open && (
                <div className="absolute right-0 mt-2 w-80 max-w-[90vw] bg-card border border-border rounded-xl shadow-xl z-50 p-2" role="dialog" aria-label="Notifications">
                    <div className="flex items-center justify-between px-2 py-1">
                        <p className="text-xs font-bold">Notifications</p>
                        {unread > 0 && <button type="button" className="text-[11px] text-purple" onClick={() => void secopsApi.markRead(orgId).then(() => setTick((x) => x + 1))}>Mark all read</button>}
                    </div>
                    <ul className="max-h-80 overflow-y-auto divide-y divide-border">
                        {(res.data?.items ?? []).length === 0 && <li className="px-2 py-3 text-xs text-foreground-muted">No notifications.</li>}
                        {(res.data?.items ?? []).map((n) => (
                            <li key={n.id} className={`px-2 py-2 text-xs ${n.read_at ? 'text-foreground-muted' : ''}`}>
                                {n.link ? <Link href={n.link} onClick={() => setOpen(false)} className="font-semibold hover:text-purple">{n.title}</Link> : <span className="font-semibold">{n.title}</span>}
                                {n.body && <p className="mt-0.5 text-foreground-muted line-clamp-2">{n.body}</p>}
                                <p className="mt-0.5 text-[10px] text-foreground-muted">{new Date(n.created_at).toLocaleString('en-GB')}</p>
                            </li>
                        ))}
                    </ul>
                </div>
            )}
        </div>
    );
}

export const ROLE_LABEL: Record<string, string> = {
    super_admin: 'Super admin', soc_manager: 'SOC manager', analyst: 'Analyst', executive: 'Executive', portal_user: 'Client portal',
};

const PLANNED_OPEN_KEY = 'novrsoc.nav.plannedOpen';

function initials(name: string, email: string): string {
    const base = (name || email.split('@')[0]).replace(/[._-]+/g, ' ').trim();
    return base.split(/\s+/).map((p) => p[0]).join('').slice(0, 2).toUpperCase() || '?';
}

function currentItem(pathname: string): NavItem | undefined {
    const live = FOUNDATION_NAV.flatMap((s) => s.items).filter((i) => i.status === 'live');
    return live.filter((i) => isActive(i, pathname)).sort((a, b) => (b.href?.length ?? 0) - (a.href?.length ?? 0))[0];
}

function ThemeToggle() {
    const { resolvedTheme, setTheme } = useTheme();
    const dark = resolvedTheme === 'dark';
    return (
        <button type="button" onClick={() => setTheme(dark ? 'light' : 'dark')} aria-label={dark ? 'Switch to light mode' : 'Switch to dark mode'}
            className="p-2 rounded-lg text-foreground-muted hover:text-foreground hover:bg-card-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-purple/60">
            {dark ? <Sun className="w-4 h-4" aria-hidden /> : <Moon className="w-4 h-4" aria-hidden />}
        </button>
    );
}

function OrgSwitcher() {
    const { orgs, orgId, switchOrg, session } = useSession();
    if (orgs.length <= 1) {
        return (
            <span className="flex items-center gap-1.5 min-w-0 text-sm font-semibold text-foreground" data-testid="active-org">
                <Building2 className="w-4 h-4 shrink-0 text-foreground-muted" aria-hidden /><span className="truncate">{session.active_org.name}</span>
            </span>
        );
    }
    return (
        <label className="flex items-center gap-1.5 min-w-0">
            <Building2 className="w-4 h-4 shrink-0 text-foreground-muted" aria-hidden />
            <span className="sr-only">Active organization</span>
            <select data-testid="org-switcher" value={orgId} onChange={(e) => switchOrg(e.target.value)}
                className="min-w-0 max-w-[14rem] truncate bg-card border border-border rounded-lg px-2 py-1.5 text-sm font-semibold text-foreground focus:outline-none focus:ring-2 focus:ring-purple/40">
                {orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
            </select>
        </label>
    );
}

function NavLink({ item, pathname, onNavigate }: { item: NavItem; pathname: string; onNavigate: () => void }) {
    const Icon = ICONS[item.icon];
    const active = isActive(item, pathname);
    return (
        <Link href={item.href as string} onClick={onNavigate} aria-current={active ? 'page' : undefined}
            className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors outline-none focus-visible:ring-2 focus-visible:ring-purple/60 ${active
                ? 'bg-purple text-white font-semibold shadow-sm'
                : 'text-foreground-muted hover:text-purple hover:bg-purple-tint dark:hover:text-white'}`}>
            <Icon className="w-[18px] h-[18px] shrink-0" aria-hidden />{item.label}
        </Link>
    );
}

function PlannedItem({ item }: { item: NavItem }) {
    const Icon = ICONS[item.icon];
    return (
        <li title={`In development (workstream ${item.workstream}). Not available yet.`} data-planned="true"
            className="flex items-center gap-3 pl-3 pr-2 py-2 rounded-lg text-sm text-foreground-muted/70 cursor-not-allowed select-none">
            <Icon className="w-4 h-4 shrink-0" aria-hidden />
            <span className="flex-1 truncate">{item.label}</span>
            <span className="text-[9px] font-bold uppercase tracking-wider border border-border rounded px-1.5 py-0.5">Soon<span className="sr-only">: not available yet</span></span>
        </li>
    );
}

function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
    const pathname = usePathname() ?? '/app';
    const { session, signOut } = useSession();
    const sections = visibleNav(session.permissions);
    // The shell renders only after the session is loaded in the browser, so reading storage here is safe.
    const [plannedOpen, setPlannedOpen] = useState(() => {
        try { const v = localStorage.getItem(PLANNED_OPEN_KEY); return v === null ? true : v === 'true'; } catch { return true; /* private mode */ }
    });
    const togglePlanned = () => setPlannedOpen((v) => { try { localStorage.setItem(PLANNED_OPEN_KEY, String(!v)); } catch { /* ignore */ } return !v; });

    return (
        <aside id="app-sidebar" aria-label="Main navigation" data-testid="sidebar" data-open={open ? 'true' : 'false'}
            className={`fixed inset-y-0 left-0 z-50 w-[260px] bg-card border-r border-border flex flex-col transition-transform duration-200 ease-out
                ${open ? 'translate-x-0 visible shadow-2xl' : '-translate-x-full invisible'} lg:visible lg:translate-x-0 lg:shadow-none`}>
            <div className="flex items-center justify-between px-5 py-4 border-b border-border">
                <Link href="/app" onClick={onClose} aria-label="NovrSOC overview" className="rounded-md dark:bg-white dark:px-2 dark:py-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-purple/60"><Logo size="md" /></Link>
                <button type="button" onClick={onClose} className="lg:hidden p-1.5 rounded-lg text-foreground-muted hover:bg-card-muted" aria-label="Close navigation">
                    <X className="w-5 h-5" aria-hidden />
                </button>
            </div>
            <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-5">
                {sections.map((s) => {
                    const planned = s.items.every((i) => i.status !== 'live');
                    if (!planned) {
                        return (
                            <div key={s.title}>
                                <p className="px-3 mb-2 text-[10px] font-bold uppercase tracking-widest text-foreground-muted">{s.title}</p>
                                <ul className="space-y-1">{s.items.map((i) => <li key={i.key}><NavLink item={i} pathname={pathname} onNavigate={onClose} /></li>)}</ul>
                            </div>
                        );
                    }
                    return (
                        <div key={s.title} className="border-t border-border pt-4">
                            <button type="button" onClick={togglePlanned} aria-expanded={plannedOpen} aria-controls="nav-planned"
                                className="w-full flex items-center justify-between px-3 mb-2 text-[10px] font-bold uppercase tracking-widest text-foreground-muted hover:text-foreground rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-purple/60">
                                {s.title}<ChevronDown className={`w-3.5 h-3.5 transition-transform ${plannedOpen ? '' : '-rotate-90'}`} aria-hidden />
                            </button>
                            {plannedOpen && <ul id="nav-planned" className="space-y-0.5">{s.items.map((i) => <PlannedItem key={i.key} item={i} />)}</ul>}
                        </div>
                    );
                })}
            </nav>
            <div className="border-t border-border px-4 py-3.5 flex items-center gap-3" data-testid="user-card">
                <span className="w-9 h-9 rounded-full bg-purple text-white text-xs font-bold flex items-center justify-center shrink-0" aria-hidden>
                    {initials(session.user.display_name, session.user.email)}
                </span>
                <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-foreground truncate" data-testid="whoami">{session.user.display_name || session.user.email}</p>
                    <p className="text-xs text-foreground-muted truncate">{ROLE_LABEL[session.role] ?? session.role} · {session.home_org.name}</p>
                </div>
                <Link href="/app/account" onClick={onClose} aria-label="Account and password" title="Account and password" data-testid="account-link"
                    className="p-2 rounded-lg text-foreground-muted hover:text-foreground hover:bg-card-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-purple/60">
                    <KeyRound className="w-4 h-4" aria-hidden />
                </Link>
                <button type="button" onClick={() => void signOut()} aria-label="Sign out" title="Sign out"
                    className="p-2 rounded-lg text-foreground-muted hover:text-red hover:bg-card-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-purple/60">
                    <LogOut className="w-4 h-4" aria-hidden />
                </button>
            </div>
        </aside>
    );
}

export function AppShell({ children }: { children: ReactNode }) {
    const pathname = usePathname() ?? '/app';
    const { session } = useSession();
    const [navOpen, setNavOpen] = useState(false);
    const menuButton = useRef<HTMLButtonElement>(null);
    const close = useCallback(() => setNavOpen(false), []);
    const item = currentItem(pathname);
    const section = FOUNDATION_NAV.find((s) => item && s.items.includes(item))?.title;

    const [navPath, setNavPath] = useState(pathname);
    if (navPath !== pathname) { setNavPath(pathname); setNavOpen(false); } // close the drawer on navigation
    useEffect(() => {
        if (!navOpen) return;
        const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') { setNavOpen(false); menuButton.current?.focus(); } };
        window.addEventListener('keydown', onKey);
        return () => window.removeEventListener('keydown', onKey);
    }, [navOpen]);

    return (
        <div className="min-h-screen bg-surface text-foreground">
            <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[60] focus:bg-purple focus:text-white focus:px-3 focus:py-2 focus:rounded-lg">Skip to content</a>
            {navOpen && <div className="fixed inset-0 z-40 bg-black/40 lg:hidden" onClick={close} aria-hidden data-testid="nav-backdrop" />}
            <Sidebar open={navOpen} onClose={close} />
            <div className="lg:pl-[260px] min-h-screen flex flex-col">
                <header className="sticky top-0 z-30 h-14 bg-card/95 backdrop-blur border-b border-border flex items-center gap-2 sm:gap-3 px-3 sm:px-6">
                    <button ref={menuButton} type="button" onClick={() => setNavOpen(true)} aria-label="Open navigation"
                        aria-controls="app-sidebar" aria-expanded={navOpen} data-testid="nav-open"
                        className="lg:hidden p-2 -ml-1 rounded-lg text-foreground-muted hover:text-foreground hover:bg-card-muted">
                        <Menu className="w-5 h-5" aria-hidden />
                    </button>
                    <span className="lg:hidden shrink-0 rounded-md dark:bg-white dark:px-1.5 dark:py-0.5"><Logo size="sm" /></span>
                    <nav aria-label="Breadcrumb" className="hidden sm:flex items-center gap-2 min-w-0 text-sm">
                        {section && <span className="text-foreground-muted">{section}</span>}
                        {section && <span className="text-border" aria-hidden>/</span>}
                        <span className="font-semibold text-foreground truncate">{item?.label ?? 'NovrSOC'}</span>
                    </nav>
                    <div className="flex-1" />
                    {session.cross_org && (
                        <span className="hidden md:inline text-[10px] font-bold uppercase tracking-wider rounded-full px-2 py-1 bg-purple-tint text-purple dark:text-white"
                            title="You are acting for another organization. Every request is audited.">Acting for another organization</span>
                    )}
                    <OrgSwitcher />
                    <NotificationsBell />
                    <ThemeToggle />
                </header>
                <main id="main" tabIndex={-1} className="flex-1 w-full max-w-7xl mx-auto p-4 sm:p-6 space-y-5 outline-none">
                    {session.password_change_required ? <PasswordChangeForm required /> : children}
                </main>
            </div>
        </div>
    );
}
