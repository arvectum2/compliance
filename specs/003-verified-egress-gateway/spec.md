# Feature 003 — verified-domain egress gateway for live browser scans
Spec Kit v1.2.4 | Status: isolated gateway + owned-site internal browser pilot verified; PUBLIC NO-GO | 2026-11-05

## User stories
- Tenant operator adds a domain; a cryptographic challenge verifies
  control of the exact hostname before scheduling any live browser scan.
- Browser runs with --network none. An independently isolated gateway
  fulfils read-only requests, within an explicit authorized domain scope,
  to a pinned public IP while maintaining TLS hostname validation.
- Operator receives evidence of blocked requests without private URLs,
  cookie values or request bodies. Suspicious DNS/subresources fail closed.

## Functional requirements
- FR-003-01: owner challenge with random nonce, expiration, revocation
  and server-side verification; no self-assertion flag in public API.
- FR-003-02: immutable authorization snapshot binds tenant, hostname,
  scope, TTL, policy version and scan job.
- FR-003-03: worker cannot open outbound sockets or access gateway
  other than a narrowly scoped IPC endpoint; no direct route.continue().
- FR-003-04: every gateway request validates protocol/method, hostname,
  DNS A/AAAA set, destination port and private/reserved IP ranges;
  TCP dials pinned IP with TLS SNI/cert checked on original hostname.
- FR-003-05: deny redirects by default; each explicitly allowed redirect
  requires independent scope/IP verification; all subresources/iframes
  obey the same policy; WebRTC/WebSockets blocked.
- FR-003-06: kernel-level outbound policy denies private, loopback,
  link-local, cloud metadata ranges even if application checks fail.
- FR-003-07: job caps: concurrent scans, page count, body bytes,
  per-host requests, wall time, retries and rate limits. No form POST.
- FR-003-08: audit trail stores decisions, minimal host/count and hashes,
  not secrets, user PII, cookie names/values or full request paths.
- FR-003-09: gateway failure, stale authorization or DNS ambiguity yields
  inconclusive result, not a green compliance verdict.

## Acceptance gates
- AT-003-01: challenge verification, expiry, replay and cross-tenant denial.
- AT-003-02: DNS rebinding, mixed public/private DNS answers, mapped IPv6,
  IPv6 local ranges, alternate IP encodings, redirects and subresources.
- AT-003-03: direct outbound attempts from Chromium fail at kernel layer;
  gateway firewall blocks private destinations even if policy overridden.
- AT-003-04: real owned-site read-only Chromium smoke with consent-specific
  controls explicitly approved; no URL bodies/values in stored reports.
- AT-003-05: local ARM64 and Linux x86-64 E2E pass with recorded evidence.

## Non-goals
No arbitrary public scanning, protected account login, client credential
collection, user-visible legal certifications or automated remediation.
