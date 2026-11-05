# Feature 003 task board — 2026-11-05

- [x] EG-001a DNS TXT one-use challenge, TTL, nonce hash and tenant binding.
- [x] EG-001b Restricted SQLite store, atomic verify, restart and revocation.
- [x] EG-001c HMAC-signed exact-host per-job grant with limits.
- [ ] EG-001d Real account/RBAC integration, trusted external DNS validation,
      denial-of-service limits and multi-node store. BLOCKS LIVE.
- [x] EG-002a Strict stdio IPC bridge, deny-by-default request envelope and caps.
- [ ] EG-002b Production broker job management, observability and retention.
- [x] EG-003a Temporary Linux gateway namespace with nftables output policy,
      root-to-nonroot capability drop and negative/positive kernel probes.
- [ ] EG-003b Deploy the actual gateway SERVICE in that namespace, bind
      authenticated broker, independent DNS/IPv6/subresource attack tests.
      **Hard security gate, not yet satisfied.**
- [x] EG-004a Pinned public IP, TLS hostname validation, DNS/ports/redirect denial.
- [ ] EG-004b Live redirects, subresources, iframe, CORS and WebSocket QA.
- [x] EG-005a No-network Chromium ↔ signed gateway ↔ synthetic HTML end-to-end.
- [ ] EG-005b Real domain browser flow with verified DNS proof.
- [x] EG-006a Unit negative tests, DNS rebinding, replay and malformed IPC.
- [x] EG-006b Offline Docker E2E for metadata, localhost and submit-like controls.
- [ ] EG-006c Kernel firewall bypass test, independent security review.
- [ ] EG-007 Owned arvectum.com live Chromium pilot. BLOCKED by EG-003.
- [x] EG-008a Threat model, release gates and local rollback document.
- [ ] EG-008b Production runbook, incident response and release approval.
