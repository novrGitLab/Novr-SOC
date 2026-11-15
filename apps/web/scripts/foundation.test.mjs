// Unit tests for the V2 foundation: role-aware navigation, honest error states, safe redirects.
import test from 'node:test';
import assert from 'node:assert/strict';
import { loadGraph } from './lib/ts-graph.mjs';

const nav = await loadGraph('src/foundation/navigation.ts');
const errors = await loadGraph('src/foundation/api/errors.ts');
const redirect = await loadGraph('src/foundation/session/redirect.ts');

const ANALYST = ['org:read', 'sites:read', 'alerts:read', 'cases:read', 'vms:read', 'intel:read', 'cnii:read'];
const PORTAL = ['org:read', 'vms:client', 'secops:client'];

test('navigation filters by permission and drops empty sections', () => {
    const portal = nav.visibleNav(PORTAL);
    assert.deepEqual(portal.flatMap((s) => s.items.map((i) => i.key)), ['overview', 'posture']);
    const analyst = nav.visibleNav(ANALYST).flatMap((s) => s.items.map((i) => i.key));
    assert.ok(analyst.includes('alerts') && analyst.includes('vms') && analyst.includes('vms-findings') && analyst.includes('cnii'));
    assert.ok(!analyst.includes('admin') && !analyst.includes('admin-billing'), 'administration is not for analysts');
});

test('final navigation: no planned links; CNII needs cnii:read (designation enforced by the API); no duplicate entries', () => {
    const items = nav.FOUNDATION_NAV.flatMap((s) => s.items);
    for (const i of items) {
        assert.equal(i.status, 'live', i.key);
        if (/cnii/i.test(i.key)) assert.equal(i.permission, 'cnii:read');
    }
    const hrefs = nav.liveHrefs();
    assert.equal(new Set(hrefs).size, hrefs.length, 'no duplicate top-level entries');
    assert.deepEqual(nav.FOUNDATION_NAV.map((s) => s.title), ['Workspace', 'Security operations', 'Vulnerability management',
        'NHAI threat intelligence', 'Protection', 'Assets', 'Assistant and continuity', 'Clients and administration']);
    assert.ok(!hrefs.includes('/app/soar/approvals'), 'approvals are a SOAR sub-page, not a sidebar entry');
    assert.equal(hrefs[0], '/app', 'the executive overview is the landing page');
});

test('every module sits behind its permission', () => {
    const items = nav.FOUNDATION_NAV.flatMap((s) => s.items);
    const perm = Object.fromEntries(items.map((i) => [i.key, i.permission]));
    assert.deepEqual([perm.alerts, perm.cases, perm.reports, perm.email, perm.assets, perm.chat, perm.recovery, perm.admin, perm['admin-billing'],
        perm['admin-health']], ['alerts:read', 'cases:read', 'reports:read', 'protection:read', 'assets:read', 'chat:use', 'recovery:read',
        'users:manage', 'billing:manage', 'platform:monitor']);
    const executive = nav.visibleNav(['org:read', 'sites:read', 'endpoints:read', 'reports:read', 'assets:read', 'chat:use']).flatMap((s) => s.items.map((i) => i.key));
    assert.ok(executive.includes('assets') && executive.includes('reports') && executive.includes('chat') && !executive.includes('alerts'));
});

test('active item matching', () => {
    const [overview, posture] = nav.FOUNDATION_NAV[0].items;
    assert.equal(nav.isActive(overview, '/app'), true);
    assert.equal(nav.isActive(overview, '/app/posture'), false);
    assert.equal(nav.isActive(posture, '/app/posture/detail'), true);
    assert.equal(nav.isActive(posture, '/app/postureX'), false);
});

test('API errors map to distinct honest states', () => {
    const E = errors.ApiError;
    assert.equal(errors.uiState(new E(0, 'backend_unreachable', 'x')), 'backend_unreachable');
    assert.equal(errors.uiState(new E(401, 'unauthenticated', 'x')), 'unauthorized');
    assert.equal(errors.uiState(new E(403, 'forbidden', 'x')), 'forbidden');
    assert.equal(errors.uiState(new E(404, 'not_found', 'x')), 'not_found');
    assert.equal(errors.uiState(new E(503, 'not_ready', 'x')), 'not_ready');
    assert.equal(errors.uiState(new Error('boom')), 'error');
    assert.notEqual(errors.STATE_TEXT.backend_unreachable.title, errors.STATE_TEXT.forbidden.title);
});

test('a proxy error page (non-JSON 502) is reported as unreachable, a JSON error keeps its code', async () => {
    const proxy = await errors.apiErrorFromResponse(new Response('<html>Bad gateway</html>', { status: 502 }));
    assert.equal(errors.uiState(proxy), 'backend_unreachable');
    const json = await errors.apiErrorFromResponse(new Response(JSON.stringify({ error: { code: 'forbidden', message: 'no', request_id: 'r1' } }),
        { status: 403, headers: { 'content-type': 'application/json' } }));
    assert.equal(json.code, 'forbidden'); assert.equal(json.requestId, 'r1');
});

test('post-login redirect only allows paths inside /app', () => {
    for (const bad of ['https://evil.example', '//evil.example', '/admin', '/apple', '/app\\..\\x', null, '']) {
        assert.equal(redirect.safeNext(bad), '/app', String(bad));
    }
    assert.equal(redirect.safeNext('/app/sites'), '/app/sites');
});
