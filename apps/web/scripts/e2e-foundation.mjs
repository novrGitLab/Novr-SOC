// End-to-end smoke (Phase 2, extended in Phase 4): Web -> FastAPI -> PostgreSQL -> Web, in a real headless browser.
// Phase 4 adds: dashboard from API data, endpoint inventory/detail from the labelled local fixture,
// alert -> case -> note -> status, report request/detail, cross-organization denial, mobile layouts.
// Run by scripts/e2e/run_foundation_smoke.py, which provides a disposable database, seeded users, the API
// and `next start`. Every browser request to anything other than the local web origin is refused.
//
// Env: E2E_WEB (e.g. http://127.0.0.1:3011), E2E_USER_A / E2E_PASS_A (sites:manage in org A),
//      E2E_USER_B / E2E_PASS_B (org B), E2E_ORG_A, E2E_OUT (directory for the JSON result + screenshots)
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { launchBrowser, Tab } from './browser/cdp.mjs';

const WEB = process.env.E2E_WEB;
const OUT = process.env.E2E_OUT;
const results = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
mkdirSync(OUT, { recursive: true });

function step(name, ok, detail = '') {
    results.push({ name, ok: !!ok, detail });
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`);
}

async function waitFor(tab, expr, timeout = 20000) {
    const end = Date.now() + timeout;
    while (Date.now() < end) {
        try { const v = await tab.eval(expr); if (v) return v; } catch { /* page navigating */ }
        await sleep(200);
    }
    return null;
}

async function open(port) {
    const browser = await launchBrowser({ port });
    const tab = await Tab.open(port);
    await tab.send('Page.enable');
    await tab.send('Runtime.enable');
    await tab.intercept((url) => (url.startsWith(WEB) ? 'continue' : 'block'));
    return { browser, tab };
}

const go = (tab, path) => tab.send('Page.navigate', { url: WEB + path });
const setInput = (tab, sel, value) => tab.eval(`(() => { const el = document.querySelector(${JSON.stringify(sel)});
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const set = Object.getOwnPropertyDescriptor(proto, 'value').set;
    set.call(el, ${JSON.stringify(value)}); el.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`);

async function login(tab, email, password, next = '/app/sites') {
    await go(tab, next);
    const redirected = await waitFor(tab, `location.pathname === '/login' && new URLSearchParams(location.search).get('next')`);
    await waitFor(tab, `!!document.querySelector('[data-testid=login-email]')`);
    await setInput(tab, '[data-testid=login-email]', email);
    await setInput(tab, '[data-testid=login-password]', password);
    await tab.eval(`document.querySelector('[data-testid=login-submit]').click()`);
    const landed = await waitFor(tab, `location.pathname === ${JSON.stringify(next)} && !!document.querySelector('[data-testid=whoami]')`);
    return { redirected, landed };
}

if (process.env.E2E_PHASE === 'api_down') {
    const D = await open(9343);
    try {
        await go(D.tab, '/login');
        await waitFor(D.tab, `!!document.querySelector('[data-testid=login-email]')`);
        await setInput(D.tab, '[data-testid=login-email]', 'someone@e2e.novrsoc.invalid');
        await setInput(D.tab, '[data-testid=login-password]', 'not-relevant-password');
        await D.tab.eval(`document.querySelector('[data-testid=login-submit]').click()`);
        const msg = await waitFor(D.tab, `document.querySelector('[data-testid=login-error]')?.textContent || null`);
        step('with the API stopped, sign-in explains the service cannot be reached (no crash, no fake success)',
            !!msg && /could not be reached|not ready/i.test(msg), msg ?? 'no message');
        await D.tab.screenshot(join(OUT, 'api-down-login.png'));
    } finally { await D.tab.close(); await D.browser.close(); }
    const f = results.filter((r) => !r.ok).length;
    writeFileSync(join(OUT, 'e2e-api-down-result.json'), JSON.stringify({ results, failed: f }, null, 2));
    console.log(`
${results.length - f}/${results.length} steps passed`);
    process.exit(f ? 1 : 0);
}

const siteName = `E2E-Site-${Date.now().toString(36)}`;
let siteId = null;
let caseId = null;
let reportId = null;
const noteText = `E2E note ${Date.now().toString(36)}`;
const click = (tab, sel) => tab.eval(`(() => { const el = document.querySelector(${JSON.stringify(sel)}); if (!el) return false; el.click(); return true; })()`);
const noOverflow = (tab) => tab.eval(`document.documentElement.scrollWidth <= window.innerWidth + 1`);

// ---------------------------------------------------------------- user A (organization A)
const A = await open(9341);
try {
    const r = await login(A.tab, process.env.E2E_USER_A, process.env.E2E_PASS_A);
    step('unauthenticated /app/sites is redirected to /login by the proxy', r.redirected === '/app/sites', `next=${r.redirected}`);
    step('user A signs in through the login form and lands on /app/sites', !!r.landed);
    const cookie = await A.tab.eval(`document.cookie`);
    step('session cookie is not readable by page script (httpOnly)', !/novrsoc_session=/.test(cookie) && /novrsoc_csrf=/.test(cookie));

    await waitFor(A.tab, `!!document.querySelector('[data-testid=site-name]')`);
    await setInput(A.tab, '[data-testid=site-name]', siteName);
    await setInput(A.tab, '[data-testid=site-cidrs]', '10.10.0.0/24');
    await A.tab.eval(`document.querySelector('[data-testid=site-submit]').click()`);
    siteId = await waitFor(A.tab, `(() => { const row = [...document.querySelectorAll('[data-site-id]')].find((tr) => tr.textContent.includes(${JSON.stringify(siteName)})); return row ? row.dataset.siteId : null; })()`);
    step('user A creates a site through the UI and it renders in the table (Web -> API -> DB -> Web)', !!siteId, siteId ?? 'not shown');

    await go(A.tab, `/app/sites/${siteId}`);
    const detail = await waitFor(A.tab, `document.querySelector('[data-testid=site-detail]')?.textContent.includes(${JSON.stringify(siteName)})`);
    step('user A opens the site detail page', !!detail);
    const api = await A.tab.eval(`fetch('/api/v1/sites/${siteId}', { credentials: 'same-origin' }).then(async (r) => [r.status, (await r.json()).name])`);
    step('GET /api/v1/sites/{id} through the web origin returns the record', api[0] === 200 && api[1] === siteName, String(api));
    await A.tab.screenshot(join(OUT, 'site-detail-light.png'));

    await A.tab.eval(`document.querySelector('[aria-label="Switch to dark mode"]').click()`);
    const dark = await waitFor(A.tab, `document.documentElement.classList.contains('dark')`);
    step('dark mode toggles (html.dark) and light remains the default', !!dark);
    await A.tab.screenshot(join(OUT, 'site-detail-dark.png'));

    // Responsive shell: desktop sidebar always visible; mobile off-canvas with Escape to close.
    await A.tab.eval(`document.querySelector('[aria-label="Switch to light mode"]').click()`);
    await A.tab.viewport(1280, 860);
    await go(A.tab, '/app/sites');
    await waitFor(A.tab, `!!document.querySelector('[data-testid=sites-table]')`);
    const desk = await A.tab.eval(`(() => { const s = document.querySelector('[data-testid=sidebar]'); const r = s.getBoundingClientRect();
        return { x: r.x, vis: getComputedStyle(s).visibility, links: [...document.querySelectorAll('[data-testid=module-tabs] a[aria-current=page]')].map((a) => a.textContent.trim()),
                 burger: getComputedStyle(document.querySelector('[data-testid=nav-open]')).display }; })()`);
    step('desktop: sidebar visible, the current section tab (Asset inventory / Sites) highlighted, no hamburger', desk.x === 0 && desk.vis === 'visible' && desk.links.includes('Sites') && desk.burger === 'none', JSON.stringify(desk));
    const skip = await A.tab.eval(`!!document.querySelector('a[href="#main"]') && !!document.getElementById('main')`);
    step('a "Skip to content" link targets the main region', skip);
    await A.tab.screenshot(join(OUT, 'desktop-sites-light.png'));
    await go(A.tab, '/app');
    await waitFor(A.tab, `!!document.querySelector('[data-testid=platform-kpis]') && !document.querySelector('[data-testid=platform-kpis] [aria-busy=true]')`);
    const kpi = await waitFor(A.tab, `(() => { const t = document.querySelector('[data-testid=platform-kpis]').textContent; return /Sites in this organization\\s*1(?!\\d)/.test(t) ? t : null; })()`, 8000);
    step('platform KPIs come from the API (site count shown, no placeholder figures)', !!kpi, (kpi ?? 'site count not shown').slice(0, 160));
    const exec = await waitFor(A.tab, `(() => { const k = document.querySelector('[data-testid=kpis]'); const sc = document.querySelector('[data-testid=posture-score]');
        return k && sc ? { tiles: k.querySelectorAll('[data-state]').length, unavailable: k.querySelectorAll('[data-state=unavailable]').length, score: sc.dataset.state } : null; })()`);
    step('executive overview is the landing page: explainable measurements, unavailable data never shown as zero', !!exec && exec.tiles >= 6, JSON.stringify(exec));
    await A.tab.screenshot(join(OUT, 'desktop-overview-light.png'));


    // ------------------------------------------------------------ Phase 4: dashboard, endpoints, alerts, cases, reports
    const banner = await waitFor(A.tab, `document.querySelector('[data-testid=source-banner]')?.dataset.state || null`);
    step('dashboard labels the NovrSIEM data as local fixture data (never live telemetry)', banner === 'local_fixture', String(banner));
    const ready = await waitFor(A.tab, `(() => { const r = document.querySelector('[data-testid=readiness]'); if (!r) return null;
        return [...r.querySelectorAll('[data-connector]')].map((li) => li.dataset.connector + '=' + li.dataset.state).join(','); })()`);
    // The orchestrator runs NHAI with the labelled test adapter, which the API reports as local_fixture (never connected).
    step('readiness lists connector states from the API and claims no live connection', !!ready && !/=connected/.test(ready) && /ollama=local_fixture/.test(ready), String(ready));
    const mods = await waitFor(A.tab, `(() => { const m = document.querySelector('[data-testid=modules]'); if (!m) return null;
        return Object.fromEntries([...m.querySelectorAll('[data-module]')].map((li) => [li.dataset.module, li.dataset.state])); })()`);
    step('module states from the API: built modules live; NHAI (no inference backend) not available',
        !!mods && mods.alerts === 'live' && mods.endpoints === 'live' && mods.reports === 'live' && mods.vms === 'live' && mods.soar === 'live'
        && mods.email_security === 'live' && mods.brand_protection === 'live' && mods.nhai === 'not_available' && mods.collectors === 'live'
        && mods.assets === 'live' && mods.chat === 'live', JSON.stringify(mods));
    const audited = await waitFor(A.tab, `document.querySelector('[data-testid=audit-events]')?.textContent.includes('SITE_CREATED') || null`);
    step('recent audit events on the dashboard include the site just created', !!audited);

    await go(A.tab, '/app/endpoints');
    const eps = await waitFor(A.tab, `(() => { const t = document.querySelector('[data-testid=endpoints-table]'); return t ? [...t.querySelectorAll('[data-agent-id]')].map((r) => r.dataset.agentId).sort().join(',') : null; })()`);
    step("endpoint inventory shows exactly organization A's fixture agents", eps === '001,002,003', String(eps));
    const epBanner = await A.tab.eval(`document.querySelector('[data-testid=source-banner]')?.dataset.state || null`);
    step('endpoint inventory carries the local-fixture source banner', epBanner === 'local_fixture', String(epBanner));
    await A.tab.screenshot(join(OUT, 'desktop-endpoints.png'));
    await go(A.tab, '/app/endpoints/001');
    const ep = await waitFor(A.tab, `(() => { const d = document.querySelector('[data-testid=endpoint-detail]'), s = document.querySelector('[data-testid=endpoint-sca]'), v = document.querySelector('[data-testid=endpoint-vulns]');
        return d && s && v && !v.querySelector('[aria-busy=true]') ? { os: document.querySelector('[data-testid=endpoint-os]').textContent, sca: s.textContent, vul: v.textContent } : null; })()`);
    step('endpoint detail shows OS, vulnerability summary and SCA policy', !!ep && /Ubuntu/.test(ep.os) && /cis_ubuntu22-04/.test(ep.sca) && /Total\s*17/.test(ep.vul), JSON.stringify(ep)?.slice(0, 200));

    await go(A.tab, '/app/alerts');
    const alertIds = await waitFor(A.tab, `(() => { const t = document.querySelector('[data-testid=alerts-table]'); return t ? [...t.querySelectorAll('[data-alert-id]')].map((r) => r.dataset.alertId) : null; })()`);
    const tagged = await A.tab.eval(`[...document.querySelectorAll('[data-alert-id]')].every((r) => r.querySelector('[data-testid=fixture-tag]'))`);
    step('stored alerts are listed and every fixture alert is tagged as fixture data', !!alertIds && alertIds.length > 0 && tagged, `${alertIds?.length ?? 0} alerts`);
    await A.tab.screenshot(join(OUT, 'desktop-alerts.png'));
    const alertId = alertIds?.[0];
    await go(A.tab, `/app/alerts/${alertId}`);
    await waitFor(A.tab, `!!document.querySelector('[data-testid=alert-detail]') && !!document.querySelector('[data-testid=create-case]')`);
    const noContainment = await A.tab.eval(`/only through (Novr)?SOAR on a case/i.test(document.body.textContent) && ![...document.querySelectorAll('button')].some((b) => /isolate|contain|block/i.test(b.textContent))`);
    step('desktop: an alert with a long registry-path title has no horizontal page overflow', await noOverflow(A.tab));
    step('alert detail offers no direct containment action and says response goes through SOAR with approval', noContainment);
    await click(A.tab, '[data-testid=create-case]');
    caseId = await waitFor(A.tab, `(() => { const m = /^\\/app\\/cases\\/([0-9a-f-]{36})$/.exec(location.pathname); return m && document.querySelector('[data-testid=case-alerts]') ? m[1] : null; })()`);
    const linked = caseId && await A.tab.eval(`document.querySelector('[data-testid=case-alerts] a[href="/app/alerts/${alertId}"]') !== null`);
    step('"Create case from alert" opens the new case with the alert linked', !!caseId && linked, String(caseId));
    await setInput(A.tab, '[data-testid=note-body]', noteText);
    await click(A.tab, '[data-testid=note-submit]');
    const noted = await waitFor(A.tab, `document.querySelector('[data-testid=case-timeline]')?.textContent.includes(${JSON.stringify(noteText)}) || null`);
    step('a note added to the case appears in its timeline', !!noted);
    await click(A.tab, '[data-testid=case-to-resolved]');
    const resolved = await waitFor(A.tab, `/Resolved/.test(document.querySelector('[data-testid=case-status]')?.textContent || '') && /Status changed/.test(document.querySelector('[data-testid=case-timeline]').textContent) || null`);
    step('changing the case status is reflected in the status and the timeline', !!resolved);
    const corr = await waitFor(A.tab, `document.querySelector('[data-testid=case-correlation]')?.textContent || null`);
    step('the case shows its assets and their open vulnerability findings (canonical inventory join)', !!corr, String(corr).slice(0, 160));
    step('desktop: the case page wraps long alert titles and evidence (no horizontal page overflow)', await noOverflow(A.tab));
    await A.tab.screenshot(join(OUT, 'desktop-case.png'));
    await go(A.tab, `/app/alerts/${alertId}`);
    const back = await waitFor(A.tab, `document.querySelector('[data-testid=open-case]')?.getAttribute('href') || null`);
    step('the alert now links to its case (no second case offered)', back === `/app/cases/${caseId}` && !(await A.tab.eval(`!!document.querySelector('[data-testid=create-case]')`)), String(back));

    await go(A.tab, '/app/reports');
    await waitFor(A.tab, `!!document.querySelector('[data-testid=report-submit]')`);
    await A.tab.eval(`(() => { const el = document.querySelector('[data-testid=report-form] select[aria-label=Report]');
        Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set.call(el, 'organization_summary');
        el.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);
    await click(A.tab, '[data-testid=report-submit]');
    reportId = await waitFor(A.tab, `(() => { const m = /^\\/app\\/reports\\/([0-9a-f-]{36})$/.exec(location.pathname); return m && document.querySelector('[data-testid=report-sections] [data-section]') ? m[1] : null; })()`);
    const secs = reportId && await A.tab.eval(`Object.fromEntries([...document.querySelectorAll('[data-section]')].map((s) => [s.dataset.section, s.dataset.state]))`);
    step('a requested organization summary report shows per-section source states', !!secs && secs.endpoints === 'local_fixture' && secs.cases === 'ok' && secs.sites === 'ok', JSON.stringify(secs));
    const dl = reportId && await A.tab.eval(`fetch('/api/v1/reports/${reportId}/download', { credentials: 'same-origin' }).then((r) => [r.status, r.headers.get('x-content-sha256')])`);
    step('the report download is served with its SHA-256 integrity header', !!dl && dl[0] === 200 && /^[0-9a-f]{64}$/.test(dl[1] ?? ''), String(dl));
    await A.tab.screenshot(join(OUT, 'desktop-report.png'));
    await A.tab.viewport(390, 844);
    await go(A.tab, '/app/sites');
    await waitFor(A.tab, `!!document.querySelector('[data-testid=sites-table]')`);
    const closed = await A.tab.eval(`getComputedStyle(document.querySelector('[data-testid=sidebar]')).visibility`);
    await A.tab.eval(`document.querySelector('[data-testid=nav-open]').click()`);
    const opened = await waitFor(A.tab, `document.querySelector('[data-testid=sidebar]').dataset.open === 'true' && getComputedStyle(document.querySelector('[data-testid=sidebar]')).visibility === 'visible'`);
    await sleep(400); // let the 200 ms slide-in finish before capturing
    await A.tab.screenshot(join(OUT, 'mobile-nav-open.png'), { fullPage: false });
    await A.tab.send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
    const reclosed = await waitFor(A.tab, `document.querySelector('[data-testid=sidebar]').dataset.open === 'false'`);
    step('mobile: navigation is off-canvas, opens from the menu button and closes with Escape', closed === 'hidden' && !!opened && !!reclosed, `closed=${closed}`);
    const overflow = await A.tab.eval(`document.documentElement.scrollWidth <= window.innerWidth + 1`);
    step('mobile: no horizontal page overflow', overflow);
    await A.tab.screenshot(join(OUT, 'mobile-sites.png'), { fullPage: false });
    for (const path of ['/app', '/app/endpoints', '/app/alerts', `/app/cases/${caseId}`, `/app/reports/${reportId}`]) {
        await go(A.tab, path);
        await waitFor(A.tab, `!!document.querySelector('main h1') && !document.querySelector('main [aria-busy=true]')`);
        await sleep(300);
        step(`mobile: ${path.replace(/[0-9a-f-]{36}/, '{id}')} has no horizontal page overflow`, await noOverflow(A.tab));
    }
    await A.tab.screenshot(join(OUT, 'mobile-report.png'), { fullPage: false });
    await A.tab.viewport(1280, 860);
} finally { await A.tab.close(); await A.browser.close(); }

// ---------------------------------------------------------------- pilot modules (manager + analyst of organization A)
let soarRunId = null;
const api = (tab, method, path, body) => tab.eval(`(async () => {
    const csrf = decodeURIComponent((document.cookie.split('; ').find((c) => c.startsWith('novrsoc_csrf=')) || '=').split('=')[1]);
    const r = await fetch(${JSON.stringify(path)}, { method: ${JSON.stringify(method)}, credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: ${body ? `JSON.stringify(${JSON.stringify(body)})` : 'undefined'} });
    let j = null; try { j = await r.json(); } catch { /* empty */ }
    return { status: r.status, body: j };
})()`);
const M = await open(9345);
const N = await open(9346);
try {
    await login(M.tab, process.env.E2E_USER_A, process.env.E2E_PASS_A, '/app');
    await login(N.tab, process.env.E2E_USER_A2, process.env.E2E_PASS_A2, '/app');
    for (const path of ['/app/soar', '/app/insights', '/app/nhai', '/app/vms', '/app/email', '/app/brand', '/app/cnii', '/app/admin', '/app/audit',
        '/app/posture', '/app/playbooks', '/app/soar/approvals', '/app/soar/ai', '/app/soar/policy', '/app/handover', '/app/sla', '/app/vms/findings',
        '/app/vms/scans', '/app/vms/risk', '/app/vms/remediation', '/app/vms/surface', '/app/vms/reports', '/app/assets', '/app/assets/collectors',
        '/app/insights/actors', '/app/insights/cves', '/app/chat', '/app/recovery', '/app/admin/exports', '/app/admin/agent-groups', '/app/cnii/authorizations', '/app/onboarding', '/app/vms/policy']) {
        await go(M.tab, path);
        const ok = await waitFor(M.tab, `location.pathname === ${JSON.stringify(path)} && !!document.querySelector('main h1') && !document.querySelector('main [aria-busy=true]')`, 30000);
        await sleep(400);
        const errs = await M.tab.eval(`[...document.querySelectorAll('main [role=alert]')].map((e) => e.textContent.trim().slice(0, 80))`);
        step(`pilot page ${path} renders from the API without error states`, !!ok && errs.length === 0, errs.join(' | '));
    }
    await M.tab.screenshot(join(OUT, 'pilot-audit.png'));
    const pol = await api(M.tab, 'PUT', '/api/v1/soar/policy', { allowed_actions: ['block_ip'], allowed_agent_groups: ['nv-alpha-servers'], live_enabled: true, approval_ttl_minutes: 60 });
    const pb = await api(M.tab, 'POST', '/api/v1/soar/playbooks', { name: 'e2e-contain-ssh', title: 'Contain SSH brute force (e2e)', triggers: { rule_ids: ['5712'], mitre: [], min_level: 0 },
        steps: [{ step_key: 'enrich', action: 'enrich_iocs' }, { step_key: 'block', action: 'block_ip' }],
        execution_policy: { modes: ['dry_run', 'live'], min_case_severity: 'low', max_runs_per_day: 20 } });
    step('manager sets the response policy and a playbook (a draft)', pol.status === 200 && pb.status === 201 && pb.body.status === 'draft', `${pol.status}/${pb.status}`);
    const v = await api(M.tab, 'POST', `/api/v1/soar/playbooks/${pb.body.id}/validate`);
    const sub = await api(M.tab, 'POST', `/api/v1/soar/playbooks/${pb.body.id}/submit`);
    const self = await api(M.tab, 'POST', `/api/v1/soar/playbooks/${pb.body.id}/review`, { decision: 'approve', note: 'my own playbook' });
    const M2 = await open(9348);
    let approved = null;
    try {
        await login(M2.tab, process.env.E2E_USER_A3, process.env.E2E_PASS_A3, '/app');
        await go(M2.tab, '/app/playbooks');
        approved = await api(M2.tab, 'POST', `/api/v1/soar/playbooks/${pb.body.id}/review`, { decision: 'approve', note: 'Reviewed: enrichment, then a block that waits for approval.' });
    } finally { await M2.tab.close(); await M2.browser.close(); }
    step('the playbook is validated and submitted; its author cannot approve it; another manager approves it',
        v.body?.status === 'validated' && sub.body?.status === 'pending_approval' && self.status === 403 && approved?.body?.status === 'approved',
        `${v.body?.status}/${sub.body?.status}/${self.status}/${approved?.body?.status}`);
    const alerts = await api(N.tab, 'GET', '/api/v1/soc/alerts?limit=200');
    const brute = alerts.body.items.find((a) => a.rule_id === '5712');
    const kase = await api(N.tab, 'POST', '/api/v1/soc/cases', { alert_ids: [brute.id], title: 'E2E SSH brute force', severity: brute.severity, source: 'alert', source_id: `e2e-${brute.id}` });
    const caseId2 = kase.body.case_id;
    await go(N.tab, `/app/cases/${caseId2}`);
    const rec = await waitFor(N.tab, `document.querySelector('[data-testid=case-soar] [data-recommended=e2e-contain-ssh]')?.textContent || null`);
    step('the case recommends the matching playbook with the evidence-bound target', !!rec && rec.includes('203.0.113.45'), (rec ?? '').slice(0, 120));
    await setInput(N.tab, '[data-testid=run-justification]', 'Repeated SSH failures from one source on a server.');
    await N.tab.eval(`document.querySelector('[data-testid=run-live]').click()`);
    // No regex here: inside this template literal "\/" would collapse to "/" and break a page-side regex literal.
    soarRunId = await waitFor(N.tab, `(() => { const p = location.pathname.split('/'); const id = p.length === 5 && p[1] === 'app' && p[2] === 'soar' && p[3] === 'runs' ? p[4] : ''; return id.length === 36 && document.querySelector('[data-testid=run-steps]') ? id : null; })()`);
    const waiting = soarRunId && await waitFor(N.tab, `document.querySelector('[data-step=block]')?.dataset.state || null`);
    step('analyst starts a live run; the consequential step waits for approval', waiting === 'awaiting_approval', String(waiting));
    await go(M.tab, '/app/soar');
    await waitFor(M.tab, `!!document.querySelector('[data-testid=approval-approve]')`);
    await setInput(M.tab, '[data-testid=approval-reason]', 'Confirmed in the auth logs.');
    await M.tab.eval(`document.querySelector('[data-testid=approval-approve]').click()`);
    // The decision request dispatches to the bridge; the pending list reloads (the button goes) once it has returned.
    await waitFor(M.tab, `!document.querySelector('[data-testid=approval-approve]')`);
    let receipt = null;
    for (let i = 0; i < 3 && !receipt; i++) {   // the run page does not poll: re-open it until the receipt is stored
        await go(M.tab, `/app/soar/runs/${soarRunId}`);
        receipt = await waitFor(M.tab, `document.querySelector('[data-testid=receipt]')?.textContent || null`, 8000);
    }
    step('another person approves; the simulated Server 1 bridge returns an executed receipt', !!receipt && /executed/.test(receipt) && /simulated/.test(receipt), receipt ?? '');
    await M.tab.screenshot(join(OUT, 'pilot-soar-receipt.png'));
    await go(N.tab, `/app/alerts/${brute.id}`);
    await waitFor(N.tab, `!!document.querySelector('[data-testid=nhai-explain]')`);
    await N.tab.eval(`document.querySelector('[data-testid=nhai-explain]').click()`);
    let nhai = null;
    for (let i = 0; i < 6 && !nhai; i++) {
        await sleep(5000);
        await go(N.tab, `/app/alerts/${brute.id}`);
        nhai = await waitFor(N.tab, `document.querySelector('[data-testid=nhai-result]')?.textContent || null`, 8000);
    }
    step('NHAI explanation is produced asynchronously by the worker, labelled as the test adapter', !!nhai && /test-adapter/.test(nhai), (nhai ?? '').slice(0, 120));
    await N.tab.screenshot(join(OUT, 'pilot-alert-nhai.png'));
    await go(N.tab, '/app/nhai');
    const readiness = await waitFor(N.tab, `document.querySelector('[data-testid=nhai-readiness]')?.dataset.state || null`);
    step('NHAI analysis page shows readiness read from records (backend, worker heartbeat, queue)', !!readiness, String(readiness));
    await click(N.tab, '[data-testid=nhai-analyse-org]');
    let latest = null;
    for (let i = 0; i < 6 && !/succeeded/.test(latest ?? ''); i++) {   // the page polls while a job waits or runs
        await sleep(5000);
        latest = await waitFor(N.tab, `document.querySelector('[data-testid=nhai-latest]')?.textContent || null`, 8000);
    }
    step('a combined analysis (SIEM, VMS, assets, cases, intel, SOAR, posture) is queued and drafted by the worker', /succeeded/.test(latest ?? ''), (latest ?? '').slice(0, 120));
    await N.tab.screenshot(join(OUT, 'nhai-analysis.png'));
    await go(M.tab, '/app/assets');
    await waitFor(M.tab, `!!document.querySelector('[data-testid=agent-sync]')`);
    await M.tab.eval(`document.querySelector('[data-testid=agent-sync]').click()`);
    const assetRows = await waitFor(M.tab, `document.querySelectorAll('[data-testid=assets-table] tbody tr').length || null`, 15000);
    step('the asset inventory reconciles the NovrAgents into canonical assets', !!assetRows && assetRows >= 1, String(assetRows));
    await M.tab.screenshot(join(OUT, 'assets-inventory.png'));
    await go(N.tab, '/app/chat');
    await waitFor(N.tab, `!!document.querySelector('[data-testid=chat-input]')`);
    await setInput(N.tab, '[data-testid=chat-input]', 'Which critical and high alerts came in this month?');
    await N.tab.eval(`document.querySelector('[data-testid=chat-send]').click()`);
    const chat = await waitFor(N.tab, `(() => { const a = document.querySelector('[data-testid=chat-answer]'); return a && a.textContent.includes('[C1]') ? a.textContent.slice(0, 200) : null; })()`, 15000);
    step("NovrChat answers from the organization's records with citations", !!chat, chat ?? '');
    await N.tab.screenshot(join(OUT, 'novrchat.png'));
} finally { await M.tab.close(); await M.browser.close(); await N.tab.close(); await N.browser.close(); }

// ---------------------------------------------------------------- user B (organization B)
const B = await open(9342);
try {
    const r = await login(B.tab, process.env.E2E_USER_B, process.env.E2E_PASS_B);
    step('user B (another organization) signs in', !!r.landed);
    const listed = await waitFor(B.tab, `document.querySelector('[data-testid=sites-table]') || [...document.querySelectorAll('p')].some((p) => p.textContent === 'No sites yet') ? (document.body.textContent.includes(${JSON.stringify(siteName)}) ? 'visible' : 'absent') : null`);
    step("user A's site is absent from user B's site list", listed === 'absent', String(listed));
    await go(B.tab, `/app/sites/${siteId}`);
    const nf = await waitFor(B.tab, `document.querySelector('[data-testid=site-error]')?.textContent || null`);
    step("user B's browser shows 'Not found' for user A's site id", !!nf && nf.includes('Not found'), nf ?? '');
    const api = await B.tab.eval(`fetch('/api/v1/sites/${siteId}', { credentials: 'same-origin' }).then((r) => r.status)`);
    step("GET of user A's site as user B returns 404", api === 404, String(api));
    const sw = await B.tab.eval(`fetch('/api/v1/sites', { headers: { 'X-Org-Id': ${JSON.stringify(process.env.E2E_ORG_A)} } }).then((r) => r.status)`);
    step("user B cannot switch into organization A with X-Org-Id", sw === 403, String(sw));
    const nocsrf = await B.tab.eval(`fetch('/api/v1/sites', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'no-csrf' }) }).then((r) => r.status)`);
    step('a state-changing request without the CSRF header is refused', nocsrf === 403, String(nocsrf));
    await B.tab.screenshot(join(OUT, 'other-org-not-found.png'));
    const bRun = await B.tab.eval(`fetch('/api/v1/soar/runs/${soarRunId}').then((r) => r.status)`);
    step("organization A's SOAR run returns 404 to user B", bRun === 404, String(bRun));
    const bEps = await B.tab.eval(`fetch('/api/v1/endpoints').then((r) => r.json()).then((j) => j.items.map((i) => i.agent_id).join(','))`);
    step("user B's endpoint inventory holds only organization B's agent", bEps === '004', String(bEps));
    await go(B.tab, '/app/endpoints/001');
    const bEp = await waitFor(B.tab, `document.querySelector('[data-testid=endpoint-error]')?.textContent || null`);
    step("user B gets 'Not found' for organization A's endpoint", !!bEp && bEp.includes('Not found'), bEp ?? '');
    await go(B.tab, `/app/cases/${caseId}`);
    const bCase = await waitFor(B.tab, `document.querySelector('[data-testid=case-error]')?.textContent || null`);
    step("user B gets 'Not found' for organization A's case", !!bCase && bCase.includes('Not found'), bCase ?? '');
    const bApi = await B.tab.eval(`Promise.all(['/api/v1/soc/cases/${caseId}', '/api/v1/reports/${reportId}'].map((u) => fetch(u).then((r) => r.status)))`);
    step("organization A's case and report return 404 to user B through the API", bApi.every((x) => x === 404), String(bApi));
    const bAlerts = await B.tab.eval(`fetch('/api/v1/soc/alerts').then((r) => r.json()).then((j) => j.items.length > 0 && j.items.every((a) => a.agent_id === '004'))`);
    step("user B's alert list holds only organization B's alerts", bAlerts === true);
} finally { await B.tab.close(); await B.browser.close(); }

// ---------------------------------------------------------------- temporary password must be changed first
const T = await open(9347);
try {
    const r = await login(T.tab, process.env.E2E_USER_T, process.env.E2E_PASS_T, '/app');
    const form = await waitFor(T.tab, `!!document.querySelector('[data-testid=password-change]') && !document.querySelector('[data-testid=readiness]')`);
    step('an account with a temporary password sees only the password form after sign-in', !!r.landed && form === true);
    const blocked = await T.tab.eval(`fetch('/api/v1/sites').then(async (r) => r.status + ':' + (await r.json()).error.code)`);
    step('the API refuses other routes until the password is changed', blocked === '403:password_change_required', String(blocked));
    const fresh = 'e2e new passphrase ' + Math.random().toString(36).slice(2, 10);
    await setInput(T.tab, '[data-testid=pw-current]', process.env.E2E_PASS_T);
    await setInput(T.tab, '[data-testid=pw-new]', fresh);
    await setInput(T.tab, '[data-testid=pw-again]', fresh);
    await T.tab.eval(`document.querySelector('[data-testid=pw-submit]').click()`);
    const opened = await waitFor(T.tab, `!document.querySelector('[data-testid=password-change]') && !!document.querySelector('[data-testid=readiness]')`);
    const sites = await T.tab.eval(`fetch('/api/v1/sites').then((r) => r.status)`);
    step('after changing it in the UI the application opens and the API answers', opened === true && sites === 200, String(sites));
    await T.tab.screenshot(join(OUT, 'password-changed-overview.png'));
} finally { await T.tab.close(); await T.browser.close(); }

// ---------------------------------------------------------------- platform administrator: organization management
const PA = await open(9349);
try {
    await login(PA.tab, process.env.E2E_USER_P, process.env.E2E_PASS_P, '/app');
    await go(PA.tab, '/app/admin');
    const dir = await waitFor(PA.tab, `(() => { const t = document.querySelector('[data-testid=admin-orgs]'); return t && t.textContent.includes('E2E Alpha') && t.textContent.includes('E2E Beta') ? t.textContent : null; })()`, 30000);
    step('the organization directory lists every organization with status, onboarding and integration health', !!dir && /Active/.test(dir) && /\d+\/\d+/.test(dir), (dir ?? 'not shown').slice(0, 120));
    await go(PA.tab, `/app/admin/organizations/${process.env.E2E_ORG_A}?tab=integrations`);
    const tabs = await waitFor(PA.tab, `document.querySelectorAll('[data-testid=org-tabs] [role=tab]').length || null`);
    await waitFor(PA.tab, `!!document.querySelector('[data-testid=log-sources]') && !document.querySelector('main [aria-busy=true]')`, 30000);
    const created = await PA.tab.eval(`(async () => {
        const csrf = decodeURIComponent((document.cookie.split('; ').find((c) => c.startsWith('novrsoc_csrf=')) || '=').split('=')[1]);
        const r = await fetch('/api/v1/log-sources', { method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'X-Org-Id': ${JSON.stringify(process.env.E2E_ORG_A)} },
            body: JSON.stringify({ name: 'e2e-opnsense', kind: 'syslog', source_ip: '10.250.0.1', host: '', device_type: 'firewall', vendor: 'OPNsense',
                protocol: 'udp', port: 514, site_id: null, network: null, authorization_reference: 'E2E-AUTH-1', notes: '', enabled: true }) });
        return r.status; })()`);
    await PA.tab.eval(`location.reload()`);
    const row = await waitFor(PA.tab, `(() => { const t = document.querySelector('[data-testid=log-sources-table]'); return t && t.textContent.includes('e2e-opnsense') ? t.textContent : null; })()`, 30000);
    step('the organization page has its 8 tabs and registers a syslog source to that organization only', tabs === 8 && created === 201 && !!row && /No event yet/.test(row), `${tabs}/${created}`);
    const other = await PA.tab.eval(`fetch('/api/v1/log-sources', { headers: { 'X-Org-Id': ${JSON.stringify(process.env.E2E_ORG_B)} } }).then((r) => r.json()).then((j) => j.items.map((s) => s.name).join(','))`);
    step("the other organization does not see the source", !String(other).includes('e2e-opnsense'), String(other));
    await go(PA.tab, `/app/admin/organizations/${process.env.E2E_ORG_A}?tab=users`);
    await waitFor(PA.tab, `!!document.querySelector('[data-testid=org-members]')`, 30000);
    const members = await waitFor(PA.tab, `(() => { const t = document.querySelector('[data-testid=org-members]'); return t && t.textContent.includes('analyst.alpha@e2e') ? t.textContent : null; })()`, 20000);
    step('the users tab lists the organization members', !!members);
    await PA.tab.screenshot(join(OUT, 'org-management.png'));
} finally { await PA.tab.close(); await PA.browser.close(); }

const failed = results.filter((r) => !r.ok).length;
writeFileSync(join(OUT, 'e2e-result.json'), JSON.stringify({ web: WEB, site_name: siteName, site_id: siteId, case_id: caseId, report_id: reportId, results, failed }, null, 2));
console.log(`\n${results.length - failed}/${results.length} steps passed`);
process.exit(failed ? 1 : 0);
