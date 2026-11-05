import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  FIXTURE_ORIGIN, cookieHosts, hostCounts, permittedFixture,
  requestDecision, safeHostname,
} from '../policy.mjs';

test('fixture input is an explicit allowlist, not a filesystem path', () => {
  assert.equal(permittedFixture('consent.html'), true);
  assert.equal(permittedFixture('../.env'), false);
  assert.equal(permittedFixture('https://example.com'), false);
});
test('only exact synthetic document GET may be fulfilled', () => {
  assert.equal(requestDecision(FIXTURE_ORIGIN, 'GET', 'document').allowed, true);
  for (const [url, method, resource] of [
    ['http://127.0.0.1/secret', 'GET', 'document'],
    ['http://169.254.169.254/latest/meta-data/', 'GET', 'image'],
    ['http://10.0.0.1/private', 'GET', 'fetch'],
    ['https://compliance-fixture.invalid/redirect', 'GET', 'document'],
    [FIXTURE_ORIGIN, 'POST', 'document'],
    [FIXTURE_ORIGIN, 'GET', 'script'],
    ['https://example.com/pixel?token=LEAK', 'GET', 'fetch'],
  ]) assert.equal(requestDecision(url, method, resource).allowed, false);
});
test('no credential URLs or exotic schemes accepted', () => {
  for (const url of ['file:///etc/passwd', 'http://user:pass@example.com',
    'javascript:alert(1)', 'ftp://example.com']) {
    assert.throws(() => safeHostname(url));
  }
});
test('host counting never serializes raw cookie values', () => {
  const cookies = [{ domain: '.example.com', value: 'SECRET', name: 'token' }];
  assert.deepEqual(cookieHosts(cookies), [{ host: 'example.com', count: 1 }]);
  assert.equal(JSON.stringify(cookieHosts(cookies)).includes('SECRET'), false);
  assert.deepEqual(hostCounts(['b', 'a', 'b']), [
    { host: 'a', count: 1 }, { host: 'b', count: 2 },
  ]);
});
