# EG-003b2 — trusted authorization control plane (internal only)

Status: **implemented as a private Python library and operator CLI**.
Not integrated into a public login service, billing or multi-node database.

## Security contracts

- `TenantAuth` provisions random 256-bit bearer tokens. Only SHA-256
  digests are stored in a private SQLite file (0600). Permissions:
  `domain:verify`, `scan:create`, `domain:revoke`. Each action has
  a tenant-wide, transactional hourly quota, shared across tokens/processes.
  A trusted on-machine operator provisions these tokens; there is no
  self-signup endpoint.
- `VerifiedScanService` takes a valid token, issues a one-time 15-minute
  DNS TXT challenge for an exact normalized hostname, and requires an
  actual TXT lookup before confirming it. Failure, mismatched answer,
  expiry, unknown tenant, replay or revocation deny future grants.
- Production-default TXT reader is HTTPS-only via two fixed endpoints:
  Cloudflare and Google DNS JSON APIs. TLS certificate validation,
  redirect denial, 16KB max response, DNS TXT record-name/type validation,
  complete identical result sets and a request deadline are enforced.
  This is **not DNSSEC** and still needs deployment DNS monitoring.
- Only a confirmed, tenant-owned proof can create a signed short-lived
  `gateway-v2` scan grant. It carries exact host, job, proof, expiry,
  request and byte quotas; the gateway verifies the HMAC before use.
- Signed `gateway-v2` scopes limit requests to the root document and
  same-origin static CSS/JS/images/fonts without query parameters,
  path traversal or unsafe endpoints. Forms and XHR/GET API calls
  are denied; external domains remain forbidden.

## Private operator CLI (never expose through HTTP)

```sh
# Any private local folder, created as mode 0700:
arvectum-compliance-admin --state-dir /path/to/private-state \
  provision --tenant internal_qa

# The command prints a token FILE PATH, never the token itself.
arvectum-compliance-admin --state-dir /path/to/private-state \
  challenge --token-file /path/to/private-state/tenant-internal_qa.token \
  --host example.com

# Publish the exact TXT name/value shown, then confirm through real DNS:
arvectum-compliance-admin --state-dir /path/to/private-state \
  confirm --token-file /path/to/private-state/tenant-internal_qa.token \
  --proof-id <challenge-id>

# Then issue a short-lived, privately stored signed capability:
arvectum-compliance-admin --state-dir /path/to/private-state \
  grant --token-file /path/to/private-state/tenant-internal_qa.token \
  --proof-id <verified-id> --job-id job_1 \
  --output /path/to/private-state/job_1.json
```

All state and grant files are 0600. Keep operator state outside the
repository and out of Docker build contexts. Tokens have short lifetimes;
the signing key must be backed up through a proper secret manager before
deployment, not committed to Git.

## Real DNS check on Mac mini

A read-only query for `_arvectum-compliance.arvectum.com` was sent
through Cloudflare and Google HTTPS DNS endpoints. No valid matching
ownership challenge is published there, so authorization **failed closed**.
This did not create or modify any external DNS record.

## Important deployment distinction

Earlier test modes `fixture` and `internal-owned` create an internal
synthetic proof for QA. They cannot be used as a customer verification
mechanism. The new control plane never falls back to those test proofs.
The actual browser gateway is **not yet provisioned from a durable
`gateway-v2` control-plane grant**; that attested cross-container handoff,
revocation propagation, account login, tenant quotas and independent
security review are the next release blockers.

## Offline acceptance

- Wrong tenant/scope, token expiry/revocation, hashed-at-rest and
  unreadable state files.
- Atomic shared per-tenant rate limits under concurrent workers.
- DNS TXT absent/divergent/malformed/timeout, response type and TLS
  endpoint selection.
- Unverified/revoked challenge refuses scan grants.
- Signed v2 gateway blocks suspicious static resources before transport.
- CLI end-to-end with *injected fake DNS only in unit tests*, grant-file
  rights and no leaked bearer tokens.
