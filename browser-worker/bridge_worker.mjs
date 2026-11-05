// Browser stays in Docker --network none. All HTTP bodies arrive over stdio
// via a trusted gateway process. This version is FIXTURE-ONLY: no live URLs.
import { createHash } from 'node:crypto';
import { networkInterfaces } from 'node:os';
import readline from 'node:readline';
import { chromium } from 'playwright';
import { ALLOWED_FIXTURES, cookieHosts, hostCounts, safeHostname } from './policy.mjs';

const ROOT = 'https://compliance-fixture.invalid/';
const MAX_EVENTS = 120;
const fixture = process.argv[2];
if (process.platform !== 'linux' || Object.keys(networkInterfaces()).join() !== 'lo') {
  console.error('Isolated Linux loopback-only network namespace required');
  process.exit(3);
}
if (!ALLOWED_FIXTURES.has(fixture) || process.argv.length !== 3) process.exit(2);
setTimeout(() => process.exit(124), 25_000).unref();

const outstanding = new Map();
const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
input.on('line', (line) => {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg?.kind === 'reply' && Number.isSafeInteger(msg.id)) {
    const pending = outstanding.get(msg.id);
    if (pending) {
      outstanding.delete(msg.id);
      pending(msg);
    }
  }
});

let nextId = 0;
async function askGateway(url, method, resourceType) {
  if (++nextId > MAX_EVENTS) throw new Error('Event cap exceeded');
  const id = nextId;
  const response = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      outstanding.delete(id);
      reject(new Error('Gateway timeout'));
    }, 5_000);
    outstanding.set(id, (reply) => {
      clearTimeout(timer);
      resolve(reply);
    });
  });
  process.stdout.write(JSON.stringify({
    kind: 'fetch', id, url, method, resource_type: resourceType,
  }) + '\n');
  return response;
}

let rootHash;
let browser;
async function observe(phase) {
  const context = await browser.newContext({
    javaScriptEnabled: true, acceptDownloads: false, serviceWorkers: 'block',
  });
  if (typeof context.routeWebSocket === 'function') {
    await context.routeWebSocket('**/*', (ws) => ws.close());
  }
  let page;
  const attempted = [];
  const blocked = [];
  try {
    await context.route('**/*', async (route) => {
      const request = route.request();
      let host;
      try { host = safeHostname(request.url()); }
      catch { host = '(invalid)'; }
      attempted.push(host);
      const method = request.method();
      if (
        attempted.length > MAX_EVENTS
        || method !== 'GET'
        || !['document', 'stylesheet', 'script', 'image', 'fetch', 'xhr'].includes(
          request.resourceType())
      ) {
        blocked.push(host);
        await route.abort('blockedbyclient');
        return;
      }
      try {
        const response = await askGateway(request.url(), method, request.resourceType());
        if (
          response.kind !== 'reply' || response.allowed !== true
          || typeof response.body_b64 !== 'string'
          || typeof response.content_type !== 'string'
          || response.body_b64.length > 1_500_000
        ) {
          blocked.push(host);
          await route.abort('blockedbyclient');
          return;
        }
        const body = Buffer.from(response.body_b64, 'base64');
        if (request.resourceType() === 'document' && request.url() === ROOT) {
          rootHash = createHash('sha256').update(body).digest('hex');
        }
        await route.fulfill({
          status: response.status, contentType: response.content_type, body,
        });
      } catch {
        blocked.push(host);
        await route.abort('blockedbyclient');
      }
    });
    context.on('page', (opened) => {
      if (page && opened !== page) void opened.close().catch(() => {});
    });
    page = await context.newPage();
    await page.goto(ROOT, { waitUntil: 'domcontentloaded', timeout: 8_000 });
    await page.waitForTimeout(180);
    if (phase !== 'baseline') {
      const selector = '[data-compliance-action="' + phase + '"]';
      const btn = page.locator(selector);
      if (await btn.count() !== 1) return null;
      const safe = await btn.evaluate((el) => (
        el.tagName === 'BUTTON' && el.type === 'button' && !el.closest('form')
      ));
      if (!safe) return null;
      await btn.click({ timeout: 2_000 });
      await page.waitForTimeout(180);
    }
    const cookies = await context.cookies();
    return {
      phase, requests: hostCounts(attempted), blocked: hostCounts(blocked),
      cookies: cookieHosts(cookies),
    };
  } finally {
    await context.close();
  }
}

try {
  browser = await chromium.launch({ headless: true, timeout: 12_000 });
  const baseline = await observe('baseline');
  const rejected = await observe('reject');
  const accepted = await observe('accept');
  const report = {
    schema_version: '1.0',
    scenario_version: '0.1.0',
    browser: 'chromium',
    browser_version: browser.version(),
    generated_at: new Date().toISOString(),
    source_sha256: rootHash,
    network_mode: 'none',
    fixture,
    source_host: 'compliance-fixture.invalid',
    baseline, rejected, accepted,
    limitations: [
      'No public network, fixture-only gateway over stdio',
      'Blocked request hostnames count as attempts, never confirmed transmissions',
    ],
  };
  process.stdout.write(JSON.stringify({ kind: 'result', report }) + '\n');
} catch {
  // Deliberately do not serialize stack traces, URLs or page data.
  process.stdout.write(JSON.stringify({ kind: 'error', message: 'Browser job failed' }) + '\n');
  process.exitCode = 2;
} finally {
  if (browser) await browser.close();
  input.close();
}
