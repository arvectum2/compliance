// Pure, deliberately restrictive policy for offline browser fixtures.
// No network request is ever continued; only the exact synthetic main
// document is served from a local file.
export const FIXTURE_ORIGIN = 'https://compliance-fixture.invalid/';
export const ALLOWED_FIXTURES = new Set(['consent.html', 'attack.html', 'inconclusive.html', 'security.html']);
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

// Only the main tab may request a document. Nested iframes and popup
// navigations must never turn a signed root GET into arbitrary page loading.
export function permittedMainFrame(request, page) {
  if (request.resourceType() !== 'document') return true;
  try {
    return Boolean(page) && request.frame() === page.mainFrame();
  } catch {
    return false;
  }
}

const RESPONSE_MEDIA = {
  document: new Set(['text/html', 'application/xhtml+xml']),
  stylesheet: new Set(['text/css']),
  script: new Set(['text/javascript', 'application/javascript',
    'application/x-javascript', 'text/ecmascript', 'application/ecmascript']),
  image: new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp',
    'image/avif', 'image/svg+xml', 'image/x-icon', 'image/vnd.microsoft.icon']),
  font: new Set(['font/woff', 'font/woff2', 'font/ttf', 'font/otf',
    'application/font-woff', 'application/font-woff2']),
};
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

// Defensive IPC validation even if the gateway reply is malformed.
// Never forward HTTP redirects, binary downloads or unexpected script MIME.
export function permittedGatewayReply(reply, resourceType) {
  if (reply?.kind !== 'reply' || reply.allowed !== true || reply.status !== 200
      || typeof reply.content_type !== 'string'
      || !/^[\x20-\x7e]{1,200}$/.test(reply.content_type)
      || typeof reply.body_b64 !== 'string' || reply.body_b64.length > 1_500_000
      || !BASE64.test(reply.body_b64)) {
    return false;
  }
  const type = reply.content_type.split(';', 1)[0].trim().toLowerCase();
  return RESPONSE_MEDIA[resourceType]?.has(type) === true;
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
