// Pure, deliberately restrictive policy for offline browser fixtures.
// No network request is ever continued; only the exact synthetic main
// document is served from a local file.
export const FIXTURE_ORIGIN = 'https://compliance-fixture.invalid/';
export const ALLOWED_FIXTURES = new Set(['consent.html', 'attack.html', 'inconclusive.html']);
export const MAX_REQUESTS = 200;

export function permittedFixture(filename) {
  return typeof filename === 'string' && ALLOWED_FIXTURES.has(filename);
}

export function safeHostname(rawUrl) {
  const parsed = new URL(rawUrl);
  if (!['https:', 'http:'].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw new Error('Unsupported network URL');
  }
  return parsed.hostname.toLowerCase().replace(/\.$/, '');
}

export function requestDecision(rawUrl, method, resourceType) {
  let host;
  try {
    host = safeHostname(rawUrl);
  } catch {
    return { allowed: false, host: '(invalid)' };
  }
  // Only synthetic fixture main document GET is served; ALL other
  // network/subresource/redirect traffic is aborted.
  const allowed = rawUrl === FIXTURE_ORIGIN
    && method === 'GET' && resourceType === 'document';
  return { allowed, host };
}

export function hostCounts(items) {
  const counts = new Map();
  for (const item of items) {
    counts.set(item, (counts.get(item) ?? 0) + 1);
  }
  return [...counts].sort(([a], [b]) => a.localeCompare(b))
    .map(([host, count]) => ({ host, count }));
}

export function cookieHosts(cookies) {
  const hosts = [];
  for (const cookie of cookies) {
    // Only domain is used; never serialize the cookie object.
    const host = cookie.domain.replace(/^\./, '').toLowerCase();
    if (!/^[a-z0-9.-]{1,253}$/.test(host)) throw new Error('Invalid cookie domain');
    hosts.push(host);
  }
  return hostCounts(hosts);
}
