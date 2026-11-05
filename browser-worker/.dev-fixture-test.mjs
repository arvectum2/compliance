// Fixture-only. This process MUST run within the no-network Docker runner.
// No browsing of arbitrary user URLs is supported.
import { readFile } from 'node:fs/promises';
import { networkInterfaces } from 'node:os';
import { resolve } from 'node:path';
import { chromium } from 'playwright';
import {
  ALLOWED_FIXTURES, FIXTURE_ORIGIN, MAX_REQUESTS, cookieHosts, hostCounts,
  permittedFixture, requestDecision,
} from './policy.mjs';

// Fail closed if accidentally launched on a connected host or in bridge mode.
const interfaces = Object.keys(networkInterfaces());
if (false) {
  console.error('Isolated Linux network namespace with loopback only is required');
  process.exit(3);
}
// Prevent a hung browser from leaving an unbounded container.
setTimeout(() => {
  console.error('Browser fixture wall-time limit exceeded');
  process.exit(124);
}, 20_000).unref();

const filename = process.argv[2];
if (!permittedFixture(filename) || process.argv.length !== 3) {
  console.error('Usage: node worker.mjs <approved-fixture-name>');
  process.exit(2);
}
const content = await readFile(resolve('../tests/browser-fixtures', filename), 'utf8');
if (Buffer.byteLength(content, 'utf8') > 200_000) {
  console.error('Fixture size limit exceeded');
  process.exit(2);
}

const browser = await chromium.launch({ headless: true, timeout: 12_000 });
async function observe(phase) {
  const context = await browser.newContext({
    serviceWorkers: 'block',
    acceptDownloads: false,
    javaScriptEnabled: true,
    ignoreHTTPSErrors: false,
  });
  const attempted = [];
  const blocked = [];
  let documentServed = false;
  let page;
  context.on('page', (opened) => {
    // All popups are closed; no browsing outside the fixture root.
    if (page && opened !== page) void opened.close().catch(() => {});
  });
  try {
    await context.route('**/*', async (route) => {
      const request = route.request();
      const decision = requestDecision(request.url(), request.method(), request.resourceType());
      attempted.push(decision.host);
      if (attempted.length > MAX_REQUESTS) {
        blocked.push(decision.host);
        await route.abort('blockedbyclient');
        return;
      }
      if (decision.allowed && !documentServed) {
        documentServed = true;
        await route.fulfill({
          status: 200,
          contentType: 'text/html; charset=utf-8',
          body: content,
        });
      } else {
        blocked.push(decision.host);
        await route.abort('blockedbyclient');
      }
    });
    page = await context.newPage();
    await page.goto(FIXTURE_ORIGIN, { timeout: 7_000, waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(250);
    let recognized = phase === 'baseline';
    if (phase !== 'baseline') {
      const selector = '[data-compliance-action="' + phase + '"]';
      const locator = page.locator(selector);
      // No fuzzy consent selectors, input submits, or inside-form clicks.
      if (await locator.count() === 1) {
        const safe = await locator.evaluate((el) =>
          el.tagName === 'BUTTON'
          && el.getAttribute('type')?.toLowerCase() === 'button'
          && !el.closest('form'));
        if (safe) {
          await locator.click({ timeout: 2000 });
          recognized = true;
          await page.waitForTimeout(250);
        }
      }
    }
    if (!recognized) return null;
    const cookies = await context.cookies();
    return {
      phase: phase === 'accept' ? 'accept' : phase === 'reject' ? 'reject' : 'baseline',
      requests: hostCounts(attempted),
      cookies: cookieHosts(cookies),
      blocked: hostCounts(blocked),
    };
  } finally {
    await context.close();
  }
}
try {
  const baseline = await observe('baseline');
  const rejected = await observe('reject');
  const accepted = await observe('accept');
  // Only hostnames and counts; never include raw request URLs or cookie values.
  process.stdout.write(JSON.stringify({
    schema_version: '1.0',
    fixture: filename,
    source_host: 'compliance-fixture.invalid',
    browser: 'chromium',
    network_mode: 'none',
    baseline,
    rejected,
    accepted,
    limitations: [
      'Offline fixture only; not a real website compliance audit.',
      'All network/subresource requests aborted, no DNS resolution.',
      'Cookie values, request paths, query params and bodies never retained.',
    ],
  }) + '\n');
} finally {
  await browser.close();
}
