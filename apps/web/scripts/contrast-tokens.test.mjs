import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const CSS = readFileSync(fileURLToPath(new URL('../src/app/globals.css', import.meta.url)), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '');

function declarations(selector) {
    const out = {};
    const pattern = new RegExp(`${selector.replace('.', '\\.')}\\s*\\{([^}]*)\\}`, 'g');
    for (const match of CSS.matchAll(pattern)) {
        for (const decl of match[1].matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) {
            out[decl[1]] = decl[2].trim();
        }
    }
    return out;
}

function themeTokens(theme) {
    const base = declarations(':root');
    return theme === 'dark' ? { ...base, ...declarations(':root.dark') } : base;
}

function resolve(tokens, value, depth = 0) {
    const ref = /^var\((--[\w-]+)\)$/.exec(value);
    if (ref) {
        assert.ok(depth < 10 && tokens[ref[1]] !== undefined, `unresolved ${ref[1]}`);
        return resolve(tokens, tokens[ref[1]], depth + 1);
    }
    return value;
}

function hex(tokens, name) {
    const value = resolve(tokens, tokens[name] ?? '', 0);
    assert.match(value, /^#[0-9a-fA-F]{6}$/, `${name} must resolve to a 6-digit hex, got ${value}`);
    return value.slice(1);
}

function luminance(h) {
    const [r, g, b] = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16) / 255)
        .map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a, b) {
    const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
    return (hi + 0.05) / (lo + 0.05);
}

const TEXT_PAIRS = [
    ['foreground-muted', 'card'],
    ['foreground-muted', 'card-muted'],
    ['foreground-muted', 'surface'],
    ['foreground-muted', 'brand-purple-tint'],
    ['foreground', 'card'],
    ['foreground', 'brand-purple-tint'],
];
const SEVERITY_CHIPS = [
    ['vz-on-sev-critical', 'vz-sev-critical'],
    ['vz-on-sev-high', 'vz-sev-high'],
    ['vz-on-sev-medium', 'vz-sev-medium'],
    ['vz-on-sev-low', 'vz-sev-low'],
];

for (const theme of ['light', 'dark']) {
    test(`${theme} theme: body text and hover states meet 4.5:1`, () => {
        const tokens = themeTokens(theme);
        const failures = [];
        for (const [fg, bg] of TEXT_PAIRS) {
            const ratio = contrast(hex(tokens, `--${fg}`), hex(tokens, `--${bg}`));
            if (ratio < 4.5) failures.push(`${fg} on ${bg}: ${ratio.toFixed(2)}:1`);
        }
        assert.deepEqual(failures, []);
    });

    test(`${theme} theme: priority chip text meets 4.5:1 on each severity fill`, () => {
        const tokens = themeTokens(theme);
        const failures = [];
        for (const [ink, fill] of SEVERITY_CHIPS) {
            const ratio = contrast(hex(tokens, `--${ink}`), hex(tokens, `--${fill}`));
            if (ratio < 4.5) failures.push(`${ink} on ${fill}: ${ratio.toFixed(2)}:1`);
        }
        assert.deepEqual(failures, []);
    });
}

// ── Severity badge ───────────────────────────────────────────────────────────────────────────────
// Several severity fills sit below 3:1 against the card, so the swatch carries an outline token.
// The outline must hold 3:1 (WCAG 1.4.11) on every surface a badge appears on, and the five
// levels must stay visibly different from one another (CIE76 colour difference).
const SWATCH_SURFACES = ['card', 'card-muted', 'surface'];
const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info'];
const MIN_DELTA_E = 10;

function lab(h) {
    const [r, g, b] = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16) / 255)
        .map((v) => (v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
    const x = (r * 0.4124 + g * 0.3576 + b * 0.1805) / 0.95047;
    const y = r * 0.2126 + g * 0.7152 + b * 0.0722;
    const z = (r * 0.0193 + g * 0.1192 + b * 0.9505) / 1.08883;
    const f = (t) => (t > 0.008856 ? Math.cbrt(t) : 7.787 * t + 16 / 116);
    return [116 * f(y) - 16, 500 * (f(x) - f(y)), 200 * (f(y) - f(z))];
}
const deltaE = (a, b) => Math.hypot(...lab(a).map((v, i) => v - lab(b)[i]));

for (const theme of ['light', 'dark']) {
    test(`${theme} theme: the severity swatch outline holds 3:1 on every surface`, () => {
        const tokens = themeTokens(theme);
        const failures = [];
        for (const surface of SWATCH_SURFACES) {
            const ratio = contrast(hex(tokens, '--vz-swatch-edge'), hex(tokens, `--${surface}`));
            if (ratio < 3) failures.push(`swatch outline on ${surface}: ${ratio.toFixed(2)}:1`);
        }
        assert.deepEqual(failures, []);
    });

    test(`${theme} theme: severity levels stay distinguishable (ΔE ≥ ${MIN_DELTA_E})`, () => {
        const tokens = themeTokens(theme);
        const failures = [];
        for (let i = 0; i < SEVERITY_LEVELS.length; i++) {
            for (let j = i + 1; j < SEVERITY_LEVELS.length; j++) {
                const a = SEVERITY_LEVELS[i], b = SEVERITY_LEVELS[j];
                const d = deltaE(hex(tokens, `--vz-sev-${a}`), hex(tokens, `--vz-sev-${b}`));
                if (d < MIN_DELTA_E) failures.push(`${a} and ${b}: ΔE ${d.toFixed(1)}`);
            }
        }
        assert.deepEqual(failures, []);
    });
}
