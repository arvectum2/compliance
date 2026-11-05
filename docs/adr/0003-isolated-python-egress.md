# ADR-0003 — Python gateway inside independently firewalled namespace

Status: ACCEPTED for internal-only verified technical pilot, 2026-11-05.

## Context
The earlier stdio bridge passed browser requests through a Python gateway
running on the Mac host, while the Linux nftables namespace hosted only a
firewall test. That combination could not demonstrate a protected gateway
making real HTTPS requests.

## Decision
Build a separate `Dockerfile.gateway` from the same pinned Alpine base,
including the existing Python `GatewaySession`, `pinned_http` and offline
fixture HTML. The entrypoint sets an nftables deny policy before switching to
UID 65532 and clearing all capabilities. No ports, host sockets, or writable
bind mounts are exposed.

Chromium continues in a **different** `--network none` container. Its
stdout carries capped URL/method/resource-type requests; the host relays only
bounded IPC messages (no network fetch), and the gateway's stdin receives
them. The gateway verifies a short-lived per-job signed exact-domain grant,
applies request/byte quotas and validates the target, then either returns a
bounded body or denies the request. It can make real pinned HTTPS requests
only from behind the container's independent kernel firewall.

## Two explicit execution modes
- `fixture <approved-name>`: only synthetic .invalid test pages. Public
  outbound requests are not needed. This is the reproducible CI acceptance.
- `internal-owned`: hardcoded `https://arvectum.com/` **GET document
  only**. No subresources, redirects or other URLs may be fetched. This is
  an opt-in internal browser smoke, NOT public domain ownership verification.

The temporary internal grant is intentionally created from a test-only fake
DNS proof. No customer or arbitrary site URL can be supplied through the
scripts. Real TXT verification, identity/RBAC and persistent grant issuance
must replace this QA-only bootstrapping before any public release.

## Consequences
The firewall has been proved independently with positive and negative
TCP:443 socket controls, and the actual Python network client now executes
inside that namespace. CI tests synthetic fixtures on Linux x86-64 and Mac
mini ARM64. A separate internal opt-in run exercises a real owned-domain
HTTPS root page. Production requires additional external DNS, IPv6, tenant,
redirect and subresource security review.
