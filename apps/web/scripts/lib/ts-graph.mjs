// Test helper: compile a TypeScript or TSX module and the local files it imports, with the
// project's own TypeScript, so a component can be rendered to markup in `node --test` without a
// bundler or a new dependency. Bare packages (react, recharts, lucide-react) resolve from
// node_modules because the output lives under node_modules/.cache. `@/` maps to src/.
//
//   const { visibleNav } = await loadGraph('src/foundation/navigation.ts');
//
// Stubs replace modules that need a running Next.js app (next/link renders a plain anchor).
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const cache = join(root, 'node_modules', '.cache', 'ts-graph');

const STUBS = {
    'next/link': `import { createElement } from 'react';
export default function Link({ href, children, prefetch, scroll, replace, ...rest }) {
    return createElement('a', { href: typeof href === 'string' ? href : String(href?.pathname ?? ''), ...rest }, children);
}
`,
};

STUBS['next/navigation'] = `export const useSearchParams = () => new URLSearchParams();
export const usePathname = () => '/';
export const useRouter = () => ({ push() {}, replace() {}, back() {}, refresh() {}, prefetch() {} });
`;

// Test files run in parallel and share this cache. On Windows a file another process has open cannot be
// rewritten (EBUSY), so unchanged files are left alone and a busy one is retried briefly.
function writeCached(path, content) {
    if (existsSync(path)) { try { if (readFileSync(path, 'utf8') === content) return; } catch { /* rewrite below */ } }
    for (let attempt = 0; ; attempt++) {
        try { writeFileSync(path, content); return; } catch (e) {
            if (attempt >= 20 || !['EBUSY', 'EPERM', 'EACCES'].includes(e.code)) throw e;
            const until = Date.now() + 25 * (attempt + 1); while (Date.now() < until) { /* wait */ }
        }
    }
}

const EXTENSIONS = ['.tsx', '.ts', '/index.tsx', '/index.ts'];
const SPECIFIER = /(\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)(["'])([^"']+)\2/g;

function resolveLocal(spec, fromFile) {
    const base = spec.startsWith('@/') ? join(root, 'src', spec.slice(2)) : resolve(dirname(fromFile), spec);
    for (const ext of ['', ...EXTENSIONS]) {
        const candidate = base + ext;
        if (/\.(tsx?)$/.test(candidate) && existsSync(candidate)) return candidate;
    }
    throw new Error(`ts-graph: cannot resolve ${spec} from ${relative(root, fromFile)}`);
}

const outFor = (src) => join(cache, relative(root, src)).replace(/\.tsx?$/, '.mjs');
const done = new Map();

function compile(src) {
    if (done.has(src)) return done.get(src);
    const out = outFor(src);
    done.set(src, out);
    const js = ts.transpileModule(readFileSync(src, 'utf8'), {
        compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, verbatimModuleSyntax: false },
        fileName: src,
    }).outputText.replace(SPECIFIER, (whole, head, quote, spec) => {
        let target = null;
        if (STUBS[spec]) {
            target = join(cache, '_stubs', `${spec.replace(/\W+/g, '-')}.mjs`);
            mkdirSync(dirname(target), { recursive: true });
            writeCached(target, STUBS[spec]);
        } else if (spec.startsWith('@/') || spec.startsWith('.')) {
            target = compile(resolveLocal(spec, src));
        }
        if (!target) return whole;
        let rel = relative(dirname(out), target).split(sep).join('/');
        if (!rel.startsWith('.')) rel = `./${rel}`;
        return `${head}${quote}${rel}${quote}`;
    });
    mkdirSync(dirname(out), { recursive: true });
    writeCached(out, js);
    return out;
}

export async function loadGraph(entry) {
    return import(pathToFileURL(compile(resolve(root, entry))).href);
}

/** Does an app route such as /admin/vms/assets/abc resolve to a page.tsx under src/app?
 *  V2 Phase 2: the legacy route tree moved, unrouted, to src/extracted-routes. Its internal links
 *  (e.g. /admin/vms/...) are still checked for consistency there until a workstream re-homes them. */
export function routeHasPage(href) {
    const segments = href.split(/[?#]/)[0].split('/').filter(Boolean);
    let dirs = [join(root, 'src', 'app'), join(root, 'src', 'extracted-routes')];
    for (const segment of segments) {
        const next = [];
        for (const dir of dirs) {
            const exact = join(dir, segment);
            if (existsSync(exact)) next.push(exact);
            try {
                for (const name of readdirSync(dir)) if (/^\[[^\]]+\]$/.test(name)) next.push(join(dir, name));
            } catch { /* not a directory */ }
        }
        dirs = next;
        if (!dirs.length) return false;
    }
    return dirs.some((dir) => ['page.tsx', 'page.ts', 'page.jsx', 'page.js'].some((f) => existsSync(join(dir, f))));
}

export { root };
