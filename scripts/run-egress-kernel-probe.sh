#!/usr/bin/env bash
# Linux kernel nftables acceptance probe in an isolated, temporary container.
# Does not change the Mac host, Docker daemon firewall or other containers.
set -euo pipefail
repo="$(CDPATH='' cd "$(dirname "$0")/.." && pwd)"
if [[ "$#" -ne 0 ]]; then
  echo 'No URLs or other arguments are accepted by this safety probe' >&2
  exit 2
fi
image='arvectum/compliance-egress-probe:eg003-lite'
docker image inspect "$image" >/dev/null 2>&1 || {
  echo 'Build image first: docker build -f infra/egress/Dockerfile ...' >&2
  exit 2
}
exec docker run --rm \
  --network bridge --dns 1.1.1.1 \
  --sysctl net.ipv4.ip_unprivileged_port_start=0 \
  --cap-drop ALL --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
  --security-opt no-new-privileges:true \
  --read-only --pids-limit 64 --memory 256m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m \
  "$image"
