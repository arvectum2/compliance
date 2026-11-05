# Acceptance evidence — Feature 002 (offline scope only)

Date: 2026-11-05. Scope: B001a, B001b, B002, B003, B004.

## Executed and observed
- Docker Desktop Linux ARM64, official Playwright v1.64.1-noble image
  sha256:2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f.
- `COMPLIANCE_DOCKER_E2E=1 .venv/bin/pytest -q tests/test_browser_docker.py`
  => **3 passed**: consent (three separate contexts), hostile private/metadata
  subresources, inconclusive submit-like consent button.
- Browser requests blocked at Playwright route plus `--network none` enforced
  by Docker Linux namespace; direct network probe confirmed unreachable
  public host and 169.254.169.254.
- `pytest -q` => 54 passed, 3 skipped (the opt-in E2E).
- Node policy tests => 4 passed.
- `ruff check src tests` => passed.
- Pinned IP primitive tests include mixed public/private DNS answers,
  blocked local networks, ports, redirect and response size ceilings;
  own arvectum.com read-only pinned GET smoke passed.
- JSON contains only request/cookie host/count, fixture digest, browser
  version, generation timestamp; no names, cookie values, paths or queries.
- This evidence proves **fixture-level offline isolation only**.
  It does not show live-site browser compliance or legal conformity.

## Remaining gates
- B001c: production egress-only proxy/firewall and independent attack test
  suite (including redirect and DNS rebinding while browser requests subresources).
- Verified ownership, authorization and tenant isolation on live domains.
- B005: internal opt-in live browser observation on an owned site.
- No public SaaS launch until these gates pass.

## External CI verification
- GitHub Compliance CI: run 41995467620 SUCCESS.
- GitHub GitVerse mirror: run 41995467553 SUCCESS.
- Linux x86-64 Docker E2E: run 41995482651 SUCCESS after Bash
  entrypoint portability fix. Three tests pass with the same pinned image.
- Mac mini ARM64 Docker E2E: three tests pass with `--network none`.
- Tested implementation commit: `1d41cc64d15e2f4420a1bbefa61306b2a5fec15c`.
- Production gateway remains NO-GO; next implementation tracked at Feature 003.
