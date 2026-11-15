// Runs inside the page (serialised with toString), so it must be fully self-contained.
// Reports: horizontal overflow, controls without an accessible name, heading structure, and text
// that misses WCAG AA contrast measured from computed colours over the real rendered background.
export function audit() {
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = 1;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    const rgba = (css) => {
        ctx.clearRect(0, 0, 1, 1);
        ctx.fillStyle = '#000';
        ctx.fillStyle = css;
        ctx.fillRect(0, 0, 1, 1);
        const d = ctx.getImageData(0, 0, 1, 1).data;
        return [d[0], d[1], d[2], d[3] / 255];
    };
    const over = (top, bottom) => { const a = top[3]; return [top[0] * a + bottom[0] * (1 - a), top[1] * a + bottom[1] * (1 - a), top[2] * a + bottom[2] * (1 - a), 1]; };
    const lum = ([r, g, b]) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
    const ratio = (a, b) => { const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x); return (hi + 0.05) / (lo + 0.05); };
    const sig = (el) => `${el.tagName.toLowerCase()}${el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\s+/).slice(0, 4).join('.') : ''}`;

    // Horizontal overflow of the page (not of scroll containers inside it).
    const doc = document.documentElement;
    const scrollers = (el) => { for (let p = el.parentElement; p; p = p.parentElement) { const o = getComputedStyle(p).overflowX; if (o === 'auto' || o === 'scroll' || o === 'hidden') return true; } return false; };
    const offenders = [];
    for (const el of document.body.querySelectorAll('*')) {
        const r = el.getBoundingClientRect();
        if (r.width && r.right > doc.clientWidth + 1 && !scrollers(el) && getComputedStyle(el).position !== 'fixed') offenders.push(sig(el) + ` right=${Math.round(r.right)}`);
        if (offenders.length >= 8) break;
    }

    // Accessible names.
    const nameOf = (el) => {
        const labelled = el.getAttribute('aria-labelledby');
        if (labelled) return labelled.split(/\s+/).map((id) => document.getElementById(id)?.textContent ?? '').join(' ').trim();
        return (el.getAttribute('aria-label') || (el.labels && [...el.labels].map((l) => l.textContent).join(' ')) || el.textContent || el.getAttribute('title') || el.getAttribute('alt') || el.getAttribute('placeholder') || '').trim();
    };
    const unnamed = [];
    for (const el of document.querySelectorAll('button, a[href], input:not([type=hidden]), select, textarea, [role=button], [role=tab]')) {
        const r = el.getBoundingClientRect();
        if (!r.width || getComputedStyle(el).visibility === 'hidden') continue;
        if (!nameOf(el)) unnamed.push(sig(el));
    }
    const noAlt = [...document.querySelectorAll('img:not([alt])')].map(sig);

    // Headings.
    const headings = [...document.querySelectorAll('h1,h2,h3,h4')].filter((h) => h.getBoundingClientRect().width).map((h) => `${h.tagName}:${h.textContent.trim().slice(0, 40)}`);
    const levels = headings.map((h) => Number(h[1]));
    const skipped = levels.some((l, i) => i > 0 && l > levels[i - 1] + 1);

    // Contrast.
    const groups = new Map();
    let checked = 0;
    let skippedImages = 0;
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
        if (!n.textContent.trim()) continue;
        const el = n.parentElement;
        if (!el || el.closest('.sr-only, [aria-hidden=true], script, style, noscript')) continue;
        const rect = el.getBoundingClientRect();
        if (!rect.width || !rect.height) continue;
        const cs = getComputedStyle(el);
        if (cs.visibility === 'hidden' || cs.display === 'none') continue;
        if (el.closest(':disabled, [aria-disabled=true]')) continue;
        let opacity = 1;
        let backdrop = null;
        let image = false;
        for (let p = el; p; p = p.parentElement) {
            const s = getComputedStyle(p);
            opacity *= Number(s.opacity);
            if (s.backgroundImage !== 'none') image = true;
            const bg = rgba(s.backgroundColor);
            if (bg[3] > 0) backdrop = backdrop ? over(backdrop, bg) : bg;
            if (backdrop && backdrop[3] >= 1) break;
        }
        if (image) { skippedImages++; continue; }
        const under = backdrop ? over(backdrop, [255, 255, 255, 1]) : [255, 255, 255, 1];
        const isSvg = el instanceof SVGElement;
        const fg = rgba(isSvg ? cs.fill : cs.color);
        const text = over([fg[0], fg[1], fg[2], fg[3] * opacity], under);
        const size = parseFloat(cs.fontSize);
        const bold = Number(cs.fontWeight) >= 700;
        const need = size >= 24 || (size >= 18.66 && bold) ? 3 : 4.5;
        const got = ratio(text, under);
        checked++;
        if (got < need) {
            const key = sig(el);
            const g = groups.get(key) ?? { selector: key, count: 0, worst: 99, need, sample: '', fg: '', bg: '' };
            g.count++;
            if (got < g.worst) { g.worst = Math.round(got * 100) / 100; g.sample = n.textContent.trim().slice(0, 48); g.fg = `rgb(${text.slice(0, 3).map(Math.round)})`; g.bg = `rgb(${under.slice(0, 3).map(Math.round)})`; }
            groups.set(key, g);
        }
    }

    return {
        overflow: { scrollWidth: doc.scrollWidth, clientWidth: doc.clientWidth, page: doc.scrollWidth > doc.clientWidth + 1, offenders },
        a11y: { h1: document.querySelectorAll('h1').length, headings, skippedHeadingLevel: skipped, unnamed: [...new Set(unnamed)].slice(0, 10), noAlt },
        contrast: { checked, skippedImages, failures: [...groups.values()].sort((a, b) => a.worst - b.worst).slice(0, 12) },
        dark: doc.classList.contains('dark'),
        title: document.title,
    };
}
