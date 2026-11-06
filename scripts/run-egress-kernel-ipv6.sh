#!/usr/bin/env bash
# IPv6 socket acceptance in a disposable Linux namespace only.
set -euo pipefail
if [[ "$#" -ne 0 ]]; then exit 2; fi
image='arvectum/compliance-egress-probe:eg003-lite'
docker image inspect "$image" >/dev/null 2>&1 || exit 2
exec docker run --rm --network bridge --dns 1.1.1.1 \
  --sysctl net.ipv4.ip_unprivileged_port_start=0 \
  --cap-drop ALL --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
  --security-opt no-new-privileges:true \
  --read-only --pids-limit 64 --memory 256m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m \
  "$image" /bin/sh /opt/compliance/firewall_probe_ipv6.sh
