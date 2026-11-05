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
