# Feature 003 — experimental network-namespace egress deny policy

## Boundary
The `infra/egress/` image is a *self-contained Linux kernel firewall probe*,
NOT a deployed gateway or an arbitrary-target scanner. It is isolated from
other Docker containers and from the Mac host nftables/iptables tables.
The browser remains in a different `--network none` container.

The entrypoint is fail-closed:
1. root with narrowly scoped NET_ADMIN/SETUID/SETGID/SETPCAP capabilities loads
   nftables rules into the container network namespace;
2. nft rules deny loopback, link-local, private, metadata, reserved, mapped
   and tunneled networks. Only pinned DNS and public TCP:443 remain available;
3. `setpriv` irreversibly drops UID to 65532 and bounding/inheritable/ambient
   capabilities before launching unprivileged probe code.

The negative test opens a *real TCP listener on port 443* and tries
127.0.0.1:443 and the container private bridge IP:443. If the kernel policy
were absent, both would connect (443 is globally allowed by the output chain).
It also tests that the unprivileged worker cannot flush nftables rules.

## Invocations

```sh
docker build -f infra/egress/Dockerfile \
  -t arvectum/compliance-egress-probe:eg003-lite infra/egress
scripts/run-egress-kernel-probe.sh
COMPLIANCE_FIREWALL_E2E=1 .venv/bin/pytest -q tests/test_egress_kernel_docker.py
```

The probe never publishes a port or runs a public website scanner.

## Remaining gaps

- Need safe coupling of actual pinned_http HTTP traffic to this isolated
  gateway without reintroducing host-network access from the browser.
- Need out-of-band test covering IPv6, cloud metadata and a deliberately
  compromised application process without NET_ADMIN capabilities.
- Need full positive TLS:443 and operational policy tests on real authorized
  domains, tenant isolation, metrics, alarms, image digest pin and rollback.
- Not a production security certification.


## Independent positive/negative controls (2026-11-05)
- Without nft: an actual listener on 127.0.0.1:443 is reachable
  (negative-control exit 25); the same listener on the Docker bridge
  address is reachable (exit 26).
- With nft applied: both listeners are unreachable, even though the
  public TCP:443 rule exists. Egress code never runs with NET_ADMIN.
- The launcher temporarily grants CAP_SETPCAP to permit dropping every
  capability from the bounding set via setpriv. A first probe without
  SETPCAP revealed residual bounding capabilities, so it was corrected.
- Experimental local base: Alpine 3.24.2 (via nginx stable Alpine), with
  only nftables + util-linux added. nginx is not started.
- No firewall rules were modified on Mac mini or existing containers.

Base image pinned to nginx:stable-alpine@sha256:970364228b1e4f932abc22d321932816782cca8a20b85a77552a7cfe9acfb3b5;
currently Alpine 3.24.2 in the tested ARM64 image.
