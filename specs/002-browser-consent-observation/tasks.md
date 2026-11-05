# Feature 002 tasks — Spec Kit 1.2.4

- [x] B001a Offline Docker Chromium worker: --network none, low privileges,
  strict fixture allowlist, blocked subresource/POST, limits, security E2E.
- [x] B001b Public-address DNS validation and pinned TCP request primitive.
- [ ] B001c Production egress gateway firewall, authorization, rate limits,
  all redirects/subresources and independent network QA (Feature 003).
  **BLOCKS live SaaS.**
- [x] B002 Versioned browser evidence contract with redacted host counts.
- [x] B003 Isolated baseline / reject / accept flows on approved fixtures.
- [x] B004 Security/unit tests, real Docker smoke and negative fixtures.
- [ ] B005 Owner-approved, isolated live-site browser scan + customer-safe
  release gate. **Blocked by B001c**.
