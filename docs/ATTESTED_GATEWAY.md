# EG-003b2b — signed request handoff to an independently isolated gateway

Status: **tested offline against genuine Docker Chromium + nftables gateway**.
Not connected to customer-facing accounts, deployed tenant infrastructure or
real authenticated owned-site scans.

## Trust model

The host's `VerifiedScanService` requires a tenant-scoped token and
verified DNS TXT challenge before `gateway-v2` can be created. The HMAC
signing key and persistent SQLite proof registry stay on the trusted host.

`HostAttestor` creates an **Ed25519-signed lease** after checking that
the original HMAC grant is still valid, including proof revocation. The
lease binds tenant, job, exact hostname, proof ID/expiration, short TTL,
policy version, quotas and random nonce. The gateway container verifies
the lease using only an independent **public** Ed25519 key, mounted read-only
at `/run/compliance/attestor.pub`. The private Ed25519 key never enters
the browser or gateway container.

For **every** allowed GET, the host again checks the original grant and
current proof state. If authorized, the host signs a fresh request permit:
lease nonce, strictly increasing sequence, SHA-256 of exact URL, resource
type and expiration (at most 3 seconds). The gateway verifies this permit
**before** its own network code, then applies shared request/response caps
and strict `gateway-v2` same-origin static resource rules. Denied requests
are never forwarded to the gateway; the browser receives a generic rejection.

The gateway refuses unsigned requests, mismatched public keys, a modified
lease or permit, replays, resource/URL substitution, expired permits and
over-budget calls. Linux nftables remains an independent kernel barrier.
The browser continues in a separate `--network none` container.

## Revocation semantics

Proof revocation is read from the trusted persistent registry **before
each newly signed request**. Once revoked, the host cannot mint the next
permit; the browser job fails closed. An already issued permit is valid
for up to 3 seconds and an in-flight request may finish. Instant
cancellation of in-flight I/O requires an additional runtime cancellation
mechanism, which is NOT implemented yet.

## Proven on Docker, not in production

`run_attested_fixture` uses a test-only local SQLite registry and injected
fake TXT answers for reserved `compliance-fixture.invalid`. It creates
ephemeral 256-bit HMAC and Ed25519 keys outside the repo, starts Chromium
and gateway in separate Docker network namespaces and performs three
phases (baseline, reject, accept) when selectors are present.

Tests cover: three successful fixtures, mid-job proof revocation, tampered
lease and tampered per-request permit. No real internet or external DNS
lookup is performed by these attested fixture tests. The existing manual
`arvectum.com` pilot remains hardcoded internal QA and **does not use**
the attested grant path until real TXT ownership is approved.

## Local acceptance

```sh
docker build -f infra/egress/Dockerfile.gateway \
  -t arvectum/compliance-egress-runtime:eg003b .
COMPLIANCE_DOCKER_E2E=1 .venv/bin/pytest -q tests/test_attested_docker.py
.venv/bin/pytest -q tests/test_attested_ipc.py
```

## Production NO-GO

- Real DNS TXT proof is currently absent on `arvectum.com`.
- No production private-key manager, key rotation, per-tenant authenticated
  job executor or audited admin interface is deployed.
- No independent IPv6/DNS-resolver/redirect/subresource penetration test.
- No immediate in-flight cancellation, distributed revocation signal,
  incident response pipeline or customer billing.
- The test Docker runner accepts public-key path from its trusted
  operator; it is not a user-facing endpoint.
