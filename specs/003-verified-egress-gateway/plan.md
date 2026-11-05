# Technical plan — Feature 003

## Existing reusable components
- core/browser_evidence.py and adapters/browser_fixture.py: versioned
  sanitized evidence contract, tested with no-network Chromium.
- adapters/pinned_http.py: DNS validation, TCP IP pin, TLS hostname
  verification and redirect denial; tested independently, not deployed
  as a gateway service.
- browser-worker/worker.mjs: isolated fixture-only worker. Keep existing
  fixture mode immutable as a permanent security regression harness.
- Data Platform: generic acquisition and evidence persistence via
  published consumer contracts.

## Implementation slices
1. Domain proof service and tenant authorization snapshot. Tests first.
2. Gateway RPC schema and mutual isolation: **stdio broker** (ADR-0002),
   reject all methods except GET and unauthorized hosts.
3. Gateway container with production egress firewall, DNS pinning and
   per-request limits. Validate both address families and redirects.
4. Live Chromium adapter reading gateway responses through route.fulfill;
   browser remains --network none; no fuzzy consent clicks.
5. Negative E2E on synthetic DNS/HTTP/redirect fixtures and owned domain.
6. QA release gate with archived evidence and explicit NO-GO until passed.

## Security design decision
Do not add a general HTTP proxy or --network bridge to the browser container.
The gateway alone owns network access. Never treat route interception alone
as a security boundary. No third-party host access without a separate policy.

## CI and release
Keep existing core CI fast. Feature-specific integration tests run in
manual/required security workflows with pinned images. Launch only in
internal environment after the kernel firewall and tenant proof tests pass.

## Current evidence, 2026-11-05
EG-001a-c, EG-002a, EG-004a, EG-005a, EG-006a-b and EG-008a
implemented in reusable Python core/service and isolated Node worker.
Offline Docker E2E reaches the signed broker; the broker supplies only
synthetic fixture HTML for a reserved .invalid hostname. See acceptance.md
and docs/FEATURE003_SECURITY.md. Production EG-003 firewall remains NO-GO.

## EG-003a — independent kernel firewall prototype
- infra/egress/nftables.nft + entrypoint.sh + Dockerfile.
- Apply nft before dropping to unprivileged user; CAP_SETPCAP is needed
  to clear Linux capability bounding set (observed on Docker Desktop).
- tests/test_egress_kernel_docker.py covers both negative controls
  (kernel permits local:443 without nft) and actual deny with nft.
- A purpose-built gateway runtime and positive live-site integration
  are NOT included. EG-003b remains a release blocker.
