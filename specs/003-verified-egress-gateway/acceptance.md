# Feature 003 — acceptance evidence (offline scope)

Date: 2026-11-05. **No public/live scanner is approved.**

- Exact-host challenge: one-use 15-minute DNS TXT token; hashed at rest.
  Store requires mode 0600; atomic transition blocks replay and races.
- Signed immutable grant: tenant/job/exact-host binding, revocation check,
  <= 300-second lifetime and bounded request/byte quotas.
- Pinned HTTPS transport: all A/AAAA results checked; private, link-local,
  metadata, IPv4-mapped and 6to4 addresses refused; no redirect following.
- Chromium: --network none, read-only root, unprivileged and bounded.
  The fixture stdio broker provides synthetic HTML with signed authorization.
  Browser-submitted requests are only visible as sanitized host/count.
- Positive/negative tests on synthetic pages, no real external DNS/HTTP.
- Independent Linux x86-64 CI via Browser Docker E2E workflow.

Remaining gates: EG-001d, EG-002b, EG-003, EG-004b,
EG-005b, EG-006c, EG-007 and EG-008b. No automatic pass for unrun tests.

- EG-003a kernel probe: nftables policy installed inside a disposable Docker
  network namespace. Direct kernel-level socket tests on port 443:
  no-policy control => both loopback and bridge IP reachable (exit 25/26);
  with nft => both unreachable. Worker uid 65532, CapEff and CapBnd = 0;
  nft flush prohibited. Production EG-003b remains unimplemented.

## Independent GitHub security workflow
- Kernel firewall E2E run 42090914009: SUCCESS on Linux x86-64.
- No-firewall controls reach actual port 443 listeners; firewall denies them.
- This does not assert that EG-003b gateway production runtime is complete.


## Protected gateway end-to-end — EG-003b1
- Python GatewaySession executes inside a **separate** nftables-filtered
  Linux container; no host ports exposed.
- Chromium continues with `--network none`; messages go over stdin/stdout,
  never through an arbitrary HTTP proxy.
- Three synthetic pages pass genuine two-container E2E. A fourth negative
  case tests that internal-owned mode rejects localhost, other origins and
  subresources without making outbound HTTP.
- An opt-in **internal-owned** single-GET HTTPS pilot successfully fetched
  and rendered `https://arvectum.com/` (HTTP 200) through the gateway.
  It uses a fake, internal-only bootstrap proof; real DNS ownership verification
  has NOT occurred and no customer-facing scan is enabled.
- Docs: docs/EGRESS_GATEWAY.md and docs/adr/0003-isolated-python-egress.md.
- Public no-go: EG-001d, EG-003b2, EG-004b, EG-005b2, EG-006c, EG-007b, EG-008b.

- IPC hardening: selector reads complete lines under bounded monotonic
  deadlines; partial-line stalls and oversized frames are negative-tested.
- The dedicated Docker gateway image includes the actual Python service
  without exposing ports or accepting arbitrary target URLs.

## Trusted control plane — EG-001d1–d3, EG-003b2a

- New `service/tenant_auth.py` uses 256-bit random tokens hashed at rest,
  explicit RBAC scopes and SQLite atomic quota windows.
- `service/verified_jobs.py` requires `confirm_challenge` to perform a
  real DNS lookup before it can issue `gateway-v2` grants; in unit tests
  only, the resolver is replaced by an in-memory fixture.
- `service/dns_doh.py` queries fixed Cloudflare/Google endpoints over HTTPS;
  validates responses/record names, rejects redirects and refuses missing or
  inconsistent TXT answers. Actual `arvectum.com` read-only check returned
  **no verified proof**, correctly preventing authorization.
- `service/resource_scope.py` denies arbitrary origin, API, XHR, POST,
  paths with query strings, unsafe extensions and traversal; gateway-v2
  enforces this before fetching.
- `service/operator_cli.py` creates private 0700 state, 0600 keys/tokens
  and signed grant files with no bearer token in output.
- PUBLIC NO-GO: production account authentication, DNSSEC review,
  signed grant deployment into gateway, durable distributed storage
  and independent red-team E2E are not complete.


## Signed gateway handoff — EG-003b2b1/b2 (offline fixtures)
- `HostAttestor` signs Ed25519 leases ONLY after `GrantIssuer.require_active`
  validates HMAC and proof revocation against a trusted registry.
- Per-request signed permits bind exact URL SHA-256, resource type, monotonic
  sequence, lease nonce and at-most-3-second expiry. Proof rechecked before
  EACH new permit. Container has only Ed25519 public key (readonly mount).
- Gateway `AttestedGatewaySession` checks lease/permit cryptographically,
  independently verifies static path/host, and enforces byte/request quotas.
- Actual Chromium (--network none) ↔ host IPC ↔ nftables Python gateway E2E
  covers approved fixtures, tampering and mid-job revocation.
- Test harness creates local fake DNS proof for .invalid hostname and
  ephemeral signing keys, not production DNS or live customer traffic.
- Note: in-flight requests are not forcibly cancelled; previously issued
  permit can remain valid for up to 3 seconds. Real proof for arvectum.com
  remains absent. Production NO-GO.


## Real-proof-gated root request — EG-003b2c (2026-11-06)

- Persistent Ed25519 host identity is in private 0700 state with a 0600
  private seed; container receives only public key via read-only mount.
- SQLite `verified_method` distinguishes `doh-quorum`, `offline-test`
  and legacy data. Old schema migration does NOT promote existing proofs.
- Trusted CLI requires scoped tenant token, live unrevoked DoH proof,
  signed grant and fresh Ed25519 permit before creating Docker process.
- Gateway executes ONE exact root HTML GET from the signed hostname,
  rejecting URL/hostname/method/resource substitutions. Response stores
  only status/count/SHA; no HTML, URL queries or cookies are saved.
- Positive host-to-gateway path is simulated with signed offline fixtures;
  actual Docker negative E2E checks forged lease and missing key.
- Production DoH challenge for arvectum.com is NOT published; thus no
  newly verified live root request was executed.

## EG-003b2d — local signing key lifecycle and IPv6 kernel proof

- Persistent Ed25519 rotation writes new generation before atomically
  updating active manifest; no silent fallback on an incomplete rotation.
- Read-only shared lock protects a complete verified-root job. Nonblocking
  exclusive rotation fails during a job; stale identity fails before Docker.
- Explicit recovery requires a valid trusted active identity and removes
  only recognized abandoned artifacts, never promoting orphan keys.
- Independent direct IPv6 TCP ::1:443 test with no nftables reaches
  listener; same test with installed policy denies socket.
- Full external IPv6/NAT64 and distributed KMS key lifecycle NOT approved.


## EG-002b2a — durable worker-claim binding
The completion path compares both claimed hostname and proof ID with
the persisted job row under the lease transaction. A worker holding a
legitimate lease cannot substitute a different valid proof to evade
revocation. Negative offline regression required; distributed atomic
revocation remains a PUBLIC NO-GO.

## EG-002b3a — offline revocation sweep
- Trusted maintenance sweep denies revoked queued/running jobs and
  invalidates worker lease without storing content or raw tokens.
- Repeat is idempotent; tests cover stale worker rejection and bounded
  batches. No real DNS record or public scan is used.
- Healthy-prefix starvation, cross-database race and distributed
  revocation are explicit PUBLIC NO-GO limitations.
