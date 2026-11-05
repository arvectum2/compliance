# EG-003b — isolated Python HTTPS gateway, security acceptance

Status: internal proof of concept works; **PUBLIC NO-GO**.

## Implemented
- `infra/egress/Dockerfile.gateway` includes the Python Core/Service inside
  the independent Linux `nftables` namespace, without published ports.
- `scripts/run-egress-stdio-gateway.sh` starts a disposable, unprivileged
  after-boot, read-only container; kernel rules install before its process.
- `service/egress_worker.py` implements JSON line protocol, monotonic request
  IDs, strict method/resource filter and max 120 requests.
- A short-lived HMAC signed `GatewaySession` binds exact hostname/job and
  enforces shared response-byte and request caps. Real HTTPS is fetched using
  pinned public IP and original hostname TLS certificate verification.
- `adapters/isolated_bridge.py` relays capped IPC from no-network Chromium
  to the protected Python gateway. It performs **no network fetch on the
  Mac host** and never persists HTML, request parameters or cookie values.
- For fixtures, a fake TXT proof and synthetic HTML are used. The origin
  is reserved `compliance-fixture.invalid`.
- For internal-owned pilot, an explicitly hardcoded single URL
  `https://arvectum.com/` is permitted, and only as a main-document GET.
  Other resource types, paths, hosts, ports and methods are rejected.

## Tests run on Mac mini
```sh
docker build -f infra/egress/Dockerfile.gateway \
  -t arvectum/compliance-egress-runtime:eg003b .
COMPLIANCE_DOCKER_E2E=1 .venv/bin/pytest -q \
  tests/test_isolated_gateway_docker.py
COMPLIANCE_DOCKER_E2E=1 COMPLIANCE_OWNED_LIVE_E2E=1 \
  .venv/bin/pytest -q tests/test_isolated_gateway_docker.py \
  -k internal_owned_live_document_only
```
The owned-site HTTPS GET returned HTTP 200, text/html and the actual
48 KB root HTML (content is **not** saved to the repository).
The no-network Chromium loaded that document through the gateway;
result contains source SHA-256 and conservative baseline observation.
The live owned smoke is excluded from automatic CI to avoid unexpected
web requests and network-dependency flakes.

## Security blockers
- Internal bootstrap uses fake DNS proof. Real owner DNS TXT validation and
  tenant identity are not yet implemented in the running service.
- Egress policy and runtime need independent red-team tests covering
  IPv6, DNS resolver compromises and HTTP/TLS/subresource edge cases.
- Multi-node job management, quotas and full audit lifecycle not available.
- Browser consent interaction on real sites is not attempted.
- Neither this prototype nor the internal smoke constitutes a certified
  legal compliance conclusion or authorizes public site scanning.

The actual `nftables` firewall was tested separately with and without
rules, proving the kernel blocks direct connections to loopback/bridge
listener on TCP:443 even when application validation is bypassed.


## IPC frame hardening
The host broker now reads Docker stdout through a bounded nonblocking
selector-based line reader. Each message has a deadline and a maximum
length, including partially transmitted lines. Tests verify two buffered
frames, stalled partial frames and oversized data. Unexpected messages
fail closed; all Docker children are terminated after the test.

## CI
`.github/workflows/browser-docker-e2e.yml` builds the isolated Python
gateway image, runs synthetic two-container E2E, existing fixture checks
and the read-only negative checks of the internal-owned mode. It never
runs the live-site test without the explicit local opt-in variable.
