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
