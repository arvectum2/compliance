# EG-003b2c — persistent signing identity and real-DNS-gated root probe

Status: **offline verified; live real-domain gate remains NO-GO** because
no owner DNS TXT challenge is currently published.

## Trust boundary

The trusted operator stores Ed25519 keys in its private 0700 state
directory: a 0600 private seed and matching 0644 public key. Keys are
created explicitly once, persist across restarts, and are never replaced
silently. The private key is NEVER mounted in Docker or written to Git.

A `verified-root` invocation first authenticates the scoped tenant token,
obtains a signed `gateway-v2` grant from the persistent domain-proof store,
and then verifies **how** the proof was obtained. SQLite now records
`verified_method`: `doh-quorum`, `offline-test` or `legacy`. Existing
records migrate to `legacy`. Only a real dual-provider DoH confirmation
(`doh-quorum`) authorizes a real HTTPS root request. An old proof or one
confirmed with an injected fake resolver fails BEFORE Docker starts.

The gateway receives an Ed25519 lease and a fresh signed request permit
issued only after revocation checks. Its hostname comes from the signed
lease. It permits ONE `GET https://<verified-hostname>/` with resource type
`document`, no other path, URL, method or subresource. It uses pinned public
IP, original-hostname TLS verification and an 8-second HTTP cap. The trusted
host revalidates proof after the response; it returns only hostname,
status, byte count, SHA-256, policy and job ID. No HTML is persisted.

This is an internal **one-document HTTPS smoke**, NOT a browser scan or
public multi-tenant SaaS. The old `internal-owned` mode is diagnostic-only
and cannot replace an attested real proof.

## Private operator commands

Install the optional crypto dependency with
`pip install -e '.[secure-gateway]'`. Base static scanning and DNS
administration remain usable without the optional crypto stack.

```sh
arvectum-compliance-admin --state-dir /path/to/private-state \
  provision --tenant internal_qa
arvectum-compliance-admin --state-dir /path/to/private-state attestor-init
arvectum-compliance-admin --state-dir /path/to/private-state attestor-info
```

Publish a real challenge shown by the `challenge` command to the
authorized DNS zone. Verify it with `confirm` using two public DoH
providers. Then, while that confirmation is still active:

```sh
arvectum-compliance-admin --state-dir /path/to/private-state \
  verified-root --token-file /path/to/private-state/tenant-internal_qa.token \
  --proof-id VERIFIED_ID --job-id root_probe_01
```

If no real proof exists, the request is denied without starting Docker.
No DNS records, production tokens or keys were created during these tests.

## Acceptance and remaining gates

- Key restart consistency, symlinks, file modes, pair mismatch, duplicate
  or concurrent initialization are tested.
- Old SQLite schema upgrades without granting production proof privilege.
- Mocked/fixture DNS cannot trigger real-root execution; signed test
  session can return status/hash without leaking HTML.
- The verified gateway rejects altered URL, method, resource type or ID
  before network access; Docker rejects a forged lease and missing key.
- Public release still needs real DNS owner enrollment, central KMS/HSM
  and key rotation, full attested browser scanning, independent IPv6/DNS
  network review, operational audit retention and incident response.
