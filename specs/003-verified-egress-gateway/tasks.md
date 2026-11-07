# Feature 003 task board — 2026-11-05

- [x] EG-001a DNS TXT one-use challenge, TTL, nonce hash and tenant binding.
- [x] EG-001b Restricted SQLite store, atomic verify, restart and revocation.
- [x] EG-001c HMAC-signed exact-host per-job grant with limits.
- [x] EG-001d1 Internal tenant-scoped bearer token registry, role scopes
      and atomic per-tenant hourly quotas (single-host SQLite).
- [x] EG-001d2 Real DNS-over-HTTPS TXT agreement from independent TLS
      resolvers; missing DNS proof rejects scan authorization.
- [x] EG-001d3 Internal operator CLI with 0600 token/grant files.
- [ ] EG-001d4 Production user login/RBAC, external DNS threat review,
      multi-node datastore and signing-key management. BLOCKS PUBLIC.
- [x] EG-002a Strict stdio IPC bridge, deny-by-default request envelope and caps.
- [x] EG-002b1 Internal durable 0600 job ledger, authenticated DNS-proof
      enrollment, single-winner claim and SHA-only terminal results.
- [x] EG-002b2 Bounded tenant queue, atomic lease expiry, sanitized state
      events and 1–90-day retention, offline concurrency/revocation tests.
- [x] EG-002b2a Fail-closed durable proof/hostname binding at worker finish;
      prevent altered claim fields bypassing a revoked domain (offline).
- [x] EG-002b3a Internal offline revocation reconciliation for queued
      and running leases, sanitized events and bounded batch tests.
- [x] EG-002b3b1 Durable cursor-based bounded fair reconciliation;
      wraparound and restart tests on the internal SQLite ledger.
- [x] EG-002b3b1a Offline proof-host binding recheck at claim, finish
      and reconciliation, with corrupt-ledger fail-closed tests.
- [ ] EG-002b3b2 Cross-store atomicity, distributed revocation barrier
      and independently audited worker identity. BLOCKS PUBLIC.
- [ ] EG-002b3 Production worker integration, distributed queue/tenant
      identity, cross-DB revocation and audited telemetry. BLOCKS PUBLIC.
- [x] EG-003a Temporary Linux gateway namespace with nftables output policy,
      root-to-nonroot capability drop and negative/positive kernel probes.
- [x] EG-003b1 Python HTTPS GatewaySession runs inside the isolated
      nftables namespace; no published ports; stdio IPC to no-network browser.
- [x] EG-003b2a Separate trusted control-plane proof-to-signed-v2 grant,
      with dual DoH and strict same-origin static resource policy.
- [x] EG-003b2b1 Ed25519-attested gateway-v2 leases and per-request permits,
      public verification key mounted read-only into nftables container.
- [x] EG-003b2b2 Proof revocation rechecked before each signed request;
      real dual-container negative E2E for tamper and mid-job revocation.
- [x] EG-003b2c1 Explicit persistent Ed25519 signing identity (0700/0600)
      with no silent replacement; public key only in gateway container.
- [x] EG-003b2c2 Durable dual-DoH provenance; legacy and mock proofs
      fail closed before verified-root launch.
- [x] EG-003b2c3 Authenticated signed root-only HTTPS gateway smoke, no
      arbitrary target argument and no saved response HTML.
- [ ] EG-003b2c4 KMS/HSM rotation, real DNS-owned acceptance, independent
      IPv6/DNS/subresource testing. BLOCKS PUBLIC.
- [x] EG-004a Pinned public IP, TLS hostname validation, DNS/ports/redirect denial.
- [ ] EG-004b Live redirects, subresources, iframe, CORS and WebSocket QA.
- [x] EG-005a No-network Chromium ↔ signed gateway ↔ synthetic HTML end-to-end.
- [x] EG-005b1 Internal hardcoded arvectum.com root-document-only
      browser flow; no external DNS proof asserted.
- [ ] EG-005b2 Real browser flow with authenticated DNS proof and safe
      subresource routing.
- [x] EG-006a Unit negative tests, DNS rebinding, replay and malformed IPC.
- [x] EG-006b Offline Docker E2E for metadata, localhost and submit-like controls.
- [x] EG-006d Dual-container E2E, separate fake and real owned-target
      restrictions, bounded IPC message parsing and stalled-line tests.
- [ ] EG-006c Kernel firewall bypass test, independent security review.
- [x] EG-007a Explicit internal-owned browser pilot with GET root HTML only.
- [ ] EG-007b DNS-verified owned-site pilot, audited production network
      sandbox and multi-tenant safety gates. BLOCKS PUBLIC LAUNCH.
- [x] EG-008a Threat model, release gates and local rollback document.
- [ ] EG-008b Production runbook, incident response and release approval.

- [x] EG-003b2d1 Explicit Ed25519 key generation rotation with atomic
      active manifest and exclusive lock; verified-root holds shared lock.
- [x] EG-003b2d2 Verified crash recovery never promotes incomplete keys;
      no active key means fail closed, and operation requires confirmation.
- [x] EG-006e Independent IPv6 kernel loopback TCP:443 positive/negative
      Docker controls; confirms denied under nftables.
- [ ] EG-003b2d3 KMS/HSM, distributed locks, key backups, tenant revocation,
      IPv6 public-routing/NAT64 bypass review. BLOCKS PUBLIC.
