#!/usr/bin/env bash
# Control case: same listener probe without nft installation.
# It must FAIL at LOOPBACK_443_REACHABLE; only runs in temporary Docker netns.
set -euo pipefail
image='arvectum/compliance-egress-probe:eg003-lite'
case "$*" in
  "") skip_loopback=0 ;;
  "--bridge") skip_loopback=1 ;;
  *) exit 2 ;;
esac
exec docker run --rm --network bridge --dns 1.1.1.1 \
  --sysctl net.ipv4.ip_unprivileged_port_start=0 \
  --env "COMPLIANCE_PROBE_SKIP_LOOPBACK=$skip_loopback" \
  --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
  --security-opt no-new-privileges:true \
  --read-only --pids-limit 64 --memory 256m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m \
  --entrypoint /bin/setpriv "$image" \
  --reuid 65532 --regid 65532 --clear-groups \
  --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
  /bin/sh /opt/compliance/firewall_probe.sh
