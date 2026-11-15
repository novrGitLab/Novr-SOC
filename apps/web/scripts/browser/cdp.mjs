// Minimal Chrome DevTools Protocol driver for browser checks. No dependencies: Node's built-in
// WebSocket and fetch, and whatever Chrome or Edge is installed (CHROME_PATH overrides the lookup).
// It always launches its own headless browser with a throwaway profile, so it never attaches to
// the user's running browser, and it can refuse every request that is not the local dev server.
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CANDIDATES = [
    process.env.CHROME_PATH,
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
].filter(Boolean);

export const findChrome = () => CANDIDATES.find((p) => existsSync(p)) ?? null;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function launchBrowser({ port = 9333 } = {}) {
    const chrome = findChrome();
    if (!chrome) throw new Error('No Chrome or Edge found. Set CHROME_PATH.');
    const profile = mkdtempSync(join(tmpdir(), 'novrsoc-browser-'));
    const proc = spawn(chrome, [
        '--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check',
        '--disable-extensions', '--disable-background-networking', '--disable-sync', '--mute-audio', '--force-color-profile=srgb', 'about:blank',
    ], { stdio: 'ignore' });
    for (let i = 0; i < 60; i++) {
        try { if ((await fetch(`http://127.0.0.1:${port}/json/version`)).ok) break; } catch { /* not up yet */ }
        await sleep(250);
        if (i === 59) { proc.kill(); throw new Error('Browser did not start'); }
    }
    return {
        port,
        async close() { proc.kill(); await sleep(300); try { rmSync(profile, { recursive: true, force: true }); } catch { /* profile still locked */ } },
    };
}

export class Tab {
    static async open(port) {
        const target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: 'PUT' })).json();
        const tab = new Tab(port, target);
        await new Promise((resolve, reject) => { tab.ws.addEventListener('open', resolve, { once: true }); tab.ws.addEventListener('error', reject, { once: true }); });
        return tab;
    }

    constructor(port, target) {
        this.port = port; this.target = target; this.id = 0; this.pending = new Map(); this.handlers = new Map();
        this.ws = new WebSocket(target.webSocketDebuggerUrl);
        this.ws.addEventListener('message', (e) => {
            const msg = JSON.parse(e.data);
            if (msg.id && this.pending.has(msg.id)) {
                const { resolve, reject } = this.pending.get(msg.id); this.pending.delete(msg.id);
                msg.error ? reject(new Error(`${msg.error.message}`)) : resolve(msg.result);
            } else if (msg.method) for (const h of this.handlers.get(msg.method) ?? []) h(msg.params);
        });
    }

    send(method, params = {}) {
        const id = ++this.id;
        this.ws.send(JSON.stringify({ id, method, params }));
        return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
    }
    on(method, handler) { this.handlers.set(method, [...(this.handlers.get(method) ?? []), handler]); }

    async eval(expression) {
        const r = await this.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
        if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
        return r.result.value;
    }

    /** Fulfil or refuse every request. `decide(url, method)` returns {status, body, type?} to fulfil, 'continue', or 'block'. */
    async intercept(decide) {
        await this.send('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
        this.on('Fetch.requestPaused', async ({ requestId, request }) => {
            try {
                const d = decide(request.url, request.method);
                if (d === 'continue') await this.send('Fetch.continueRequest', { requestId });
                else if (d === 'block') await this.send('Fetch.failRequest', { requestId, errorReason: 'BlockedByClient' });
                else await this.send('Fetch.fulfillRequest', {
                    requestId, responseCode: d.status, body: Buffer.from(typeof d.body === 'string' ? d.body : JSON.stringify(d.body)).toString('base64'),
                    responseHeaders: [{ name: 'content-type', value: d.type ?? 'application/json' }, { name: 'cache-control', value: 'no-store' }],
                });
            } catch { /* the tab closed mid-request */ }
        });
    }

    async viewport(width, height = 900) {
        await this.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: width <= 768 });
    }

    async screenshot(file, { fullPage = true } = {}) {
        const { writeFileSync } = await import('node:fs');
        let clip;
        if (fullPage) {
            const m = await this.send('Page.getLayoutMetrics');
            clip = { x: 0, y: 0, width: m.cssContentSize.width, height: Math.min(m.cssContentSize.height, 6000), scale: 1 };
        }
        const { data } = await this.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: fullPage, ...(clip ? { clip } : {}) });
        writeFileSync(file, Buffer.from(data, 'base64'));
    }

    async close() {
        try { this.ws.close(); } catch { /* already closed */ }
        try { await fetch(`http://127.0.0.1:${this.port}/json/close/${this.target.id}`); } catch { /* browser closed */ }
    }
}
