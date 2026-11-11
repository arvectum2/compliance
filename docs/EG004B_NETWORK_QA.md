# EG-004b1 — offline browser/network abuse acceptance

Status: **synthetic offline E2E passed** in a Chromium container with
`--network none` and a separate nftables-protected signed Python gateway.
This does NOT constitute a live-site penetration test or production approval.

## Deny-by-default controls

- A signed `gateway-v2` request is still constrained to its exact verified
  host, HTTPS and explicitly allowed static resource paths. No external
  network request is directly continued from the browser.
- `response_policy.require_safe_response` now checks that the *gateway*
  returns precisely HTTP 200 with a MIME appropriate for the resource
  (HTML document, CSS, JavaScript, image or font). HTTP redirects (301/302/
  307/308), partial/binary/JSON substitutions, empty and malformed media
  types are denied even if the lower-level HTTP transport is mocked or
  inadvertently permits them. Failed responses consume the request quota
  but cannot increase delivered-byte accounting.
- Browser IPC independently checks response status, MIME and strict
  bounded base64 framing before `route.fulfill`.
- Chromium route handler rejects nested document/frame navigations and
  popups. A main-frame document can be loaded, but a same-origin iframe
  cannot replay the signed root GET as a new document request.
- The synthetic fixture `security.html` tries same-host and third-party
  iframes, third-party image, cross-origin CORS fetch, POST, API query,
  WebSocket and an allowed-path JavaScript URL whose mocked upstream
  response is HTTP 302. The browser blocks iframe navigation and WebSocket
  attempts, while the host/gateway reject disallowed methods, origins,
  paths and redirect/mismatched resource responses. Only sanitized host
  counts are reported; no canary token/URL/body appears in the report.

## Acceptance

```sh
.venv/bin/pytest -q tests/test_response_policy.py tests/test_attested_ipc.py
node --test browser-worker/test/policy.test.mjs
COMPLIANCE_DOCKER_E2E=1 .venv/bin/pytest -q tests/test_attested_docker.py
```

Docker acceptance requires the pinned Chromium image, installed local
Playwright dependencies and rebuilt protected gateway image. Neither the
fixture nor tests call a real third-party site, publish DNS records or
enroll customer domains.

## Remaining EG-004b2 blockers

The signed production browser session still requires genuine owner DNS
verification, a tenant-authenticated control-plane job, independently
reviewed live redirects/subresources/iframe/CORS/WebSocket behavior, and
kernel-level DNS/IPv6/NAT64 bypass audits. The current simulator is not
a substitute for external validation or legal 152-FZ compliance review.
