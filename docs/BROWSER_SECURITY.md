# Browser worker network isolation (B001/Feature 002)

## Status
Offline fixture runner targets the native Docker engine architecture (Linux ARM64 on Mac mini).
**Not yet an internet scanner**: the worker has no outbound network
and cannot inspect external sites directly. This is intentional for B001.

## Enforcement layers

1. `docker run --network none`: browser process cannot route packets to the
   host, LAN, public internet, localhost services on the Mac, or cloud metadata.
2. Worker additionally rejects execution outside Linux with loopback-only
   network namespace and enforces a 20-second wall-time watchdog.
3. `--cap-drop ALL --read-only --security-opt no-new-privileges --user pwuser`,
   PID/CPU/memory/time bounds, readonly fixture+worker mounts, tmpfs runtime.
4. Playwright `context.route('**/*')`: fulfil exactly one synthetic main-document
   GET; abort every other request including cross-origin images, fetch(), scripts
   and POST. Service workers are blocked. The route handler has no route.continue().
5. Only hardcoded non-network fixture names; no user-supplied URL, path or action.
   Only a unique explicit data-compliance-action button with type=button outside
   forms may be clicked. Missing/ambiguous action => inconclusive.
6. Output only hostnames/counts, no URL paths/queries, request bodies, cookies'
   names or values, PII or screenshots.
7. Resource ceilings: max 200 route requests, 200 kB fixture, 12s browser launch,
   7s navigation, Docker memory/PIDs/CPU caps. CLI should apply an overall time
   limit from the caller as well.

## Local verification
```sh
npm ci --prefix browser-worker --ignore-scripts
node --test browser-worker/test/policy.test.mjs
scripts/run-browser-fixture.sh consent.html
scripts/run-browser-fixture.sh attack.html
```
Requires pre-pulled `mcr.microsoft.com/playwright:v1.64.1-noble`
(pinned for execution at `sha256:2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f`).

## Production gate (NOT SATISFIED)
Live scans need a separately sandboxed, audited **egress gateway**. A draft
IP-pinned request primitive exists in adapters/pinned_http.py; it is NOT wired
into the worker or SaaS and is not a substitute for an egress firewall:
- verified domain ownership + consent and tenant quotas;
- all requests, redirects, subresources through gateway;
- DNS resolution and IP validation at every hop, pinned destination sockets
  with TLS SNI/certificate validation for the original hostname;
- gateway network policy forbidding private/loopback/link-local/metadata IPs,
  even if process-level URL checks are bypassed;
- no browser direct egress, no untrusted WebSocket/UDP/WebRTC transport;
- request/response caps, audit evidence without PII and security regression tests.
Do not allow arbitrary public website scanning in this offline worker.

## Opt-in integration QA
```sh
COMPLIANCE_DOCKER_E2E=1 .venv/bin/pytest -q tests/test_browser_docker.py
```
This gate is separate from the unit/CI tests: CI tests prove the request
policy and schema, while this opt-in gate runs a genuine browser in Docker.
The worker checks for a loopback-only Linux network namespace before launch.


## Local acceptance 2026-11-05
- Docker Linux/arm64 image pinned to the digest above.
- Three opt-in Docker Playwright E2E cases PASSED: consent fixture,
  hostile subresource requests to private/metadata addresses,
  and inconclusive submit-like consent button.
- Validated response metadata includes scenario version, browser version,
  UTC capture time and SHA-256 of the fixture.
- DNS pinned HTTP transport is exercised separately (positive/negative
  unit tests) and was smoke-tested with the Arvectum-owned website.
- This does **not** certify gateway network firewall, domain-owner proof,
  tenant quotas or real customer browser scanning.
