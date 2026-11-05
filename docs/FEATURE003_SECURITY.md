# Feature 003 — verified browser gateway

Status: **OFFLINE INTEGRATION VERIFIED; LIVE/PUBLIC NO-GO**.
Normative engineering source: specs/003-verified-egress-gateway/.

## Trust boundaries

1. **Tenant identity** — account login, RBAC and trusted service API are
   NOT integrated. Never trust tenant IDs sent directly from a browser.
2. **Ownership** — DNS TXT at _arvectum-compliance.<host> with random
   one-time 15-minute proof. SQLite store mode 0600, SHA-256 hashed nonce,
   atomic consumption, tenant binding and revocation. Existing single-node
   store is not yet a managed production multi-tenant database.
   The optional dnspython adapter is NOT DNSSEC verification and needs
   controlled trusted resolvers and abuse rate limits before deployment.
3. **Job grant** — HMAC-SHA256 signed immutable capability binds the tenant,
   job ID, exact host, verified proof+expiration, version, nonce, TTL <= 300s,
   request/byte quotas. Gateway validates revocation on every request.
4. **Browser** — pinned Chromium in Docker --network none, no capabilities,
   read-only root, CPU/memory/PID caps. No published ports or host sockets.
   Strict stdin/stdout IPC connects to the trusted host gateway. Browser
   never calls route.continue() or submits any form.
5. **Gateway** — GET only, exact verified HTTPS hostname on port 443. Shared
   per-job caps. Pinned HTTP validates all DNS answers, refuses private,
   mapped and tunneled addresses, dials validated IP without another DNS
   lookup, preserves TLS SNI/cert checks and refuses redirects.
6. **Data output** — only hostname/count, time/browser version and source
   hash; never raw URL path/query, cookie names/values or request bodies.
   Review signals are not declarations of legal violations.

## Verified scope

- Mac mini ARM64: genuine Chromium inside Docker network=none; baseline,
  rejection, consent, private/metadata IP and submit-like button fixtures.
- Three additional full Docker E2E cases via *stdio gateway broker*,
  using a fake DNS proof for a reserved .invalid fixture hostname, signed
  job grants, controlled mock HTML and strict request-scoping.
- Python tests cover replay, revocation, TTL, SQLite restart and concurrency,
  cross-tenant signatures, DNS errors, IP mapping, quotas and malformed IPC.
- GitHub's independent x86-64 Docker workflow includes both E2E suites.

## Blocking production release gates

- EG-001c: authenticated account identity, production DNS verification
  policy, rate limits and operational DB.
- EG-003b1 gateway is now actually running within nftables: the
  internal root-only `arvectum.com` browser smoke returned HTTP 200.
  **EG-003b2 remains blocked**: true domain TXT ownership, tenant identity,
  independent IPv6/DNS/subresource bypass tests and external policy review.
- EG-004b/005b: real subresources, redirects, iframes and owned-domain
  browser flow behind that gateway. WebRTC/WebSockets restricted.
- EG-006c: independent security review.
- EG-007: explicitly verified arvectum.com live browser pilot.
- EG-008b: operational alerts, retention, incident response and rollback.

**Do not expose the fixture broker as a public site scanner.**

## Test and rollback

```sh
.venv/bin/ruff check src tests
.venv/bin/pytest -q
node --test browser-worker/test/policy.test.mjs
COMPLIANCE_DOCKER_E2E=1 .venv/bin/pytest -q \
  tests/test_browser_docker.py tests/test_bridge_docker.py
```

Browser image sha256:
2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f.

No production website, external DNS, customer DB or background daemon
was modified; stopping the Docker test terminates the workflow. Roll back
through the designated Git commit. Data Platform remains unchanged.
