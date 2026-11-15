// Fails (exit 1) if a LIVE item of the V2 navigation (src/foundation/navigation.ts) has no page under
// src/app, or if a PLANNED item carries an href (planned modules must never render as links).
import { existsSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadGraph } from './lib/ts-graph.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const appDir = join(root, 'src', 'app');
const { FOUNDATION_NAV, liveHrefs } = await loadGraph('src/foundation/navigation.ts');
const isDir = (p) => existsSync(p) && statSync(p).isDirectory();

function hasPage(href) {
    let dirs = [appDir];
    for (const seg of href.split('/').filter(Boolean)) {
        const next = [];
        for (const d of dirs) {
            for (const entry of readdirSync(d)) {
                const full = join(d, entry);
                if (!isDir(full)) continue;
                if (entry === seg || /^\[[^\]]+\]$/.test(entry)) next.push(full);
                if (/^\(.+\)$/.test(entry) && isDir(join(full, seg))) next.push(join(full, seg));
            }
        }
        dirs = next;
    }
    return dirs.some((d) => ['page.tsx', 'page.ts'].some((f) => existsSync(join(d, f))));
}

const problems = [];
for (const href of liveHrefs()) if (!hasPage(href)) problems.push(`live item ${href} has no page under src/app`);
for (const s of FOUNDATION_NAV) for (const i of s.items) if (i.status === 'planned' && i.href) problems.push(`planned item ${i.key} must not have an href`);
if (problems.length) { console.error(`check-v2-nav: ${problems.length} problem(s):\n  - ${problems.join('\n  - ')}`); process.exit(1); }
console.log(`check-v2-nav: ${liveHrefs().length} live routes resolve; planned modules are not linked`);
