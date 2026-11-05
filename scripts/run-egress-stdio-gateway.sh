#!/usr/bin/env bash
# Temporary EG-003b no-port, no-file-writes, firewall-restricted gateway.
set -euo pipefail
if [[ "$#" -ne 1 && "$#" -ne 2 ]]; then
  echo 'Usage: fixture <approved-name> OR internal-owned' >&2; exit 2
fi
case "$1:${2:-}" in
  fixture:consent.html|fixture:attack.html|fixture:inconclusive.html)
     mode=fixture; fixture="$2" ;;
  internal-owned:)
     mode=internal-owned; fixture='' ;;
  *)
     echo 'Arbitrary targets are not supported' >&2; exit 2 ;;
esac
image='arvectum/compliance-egress-runtime:eg003b'
docker image inspect "$image" >/dev/null 2>&1 || {
  echo 'Gateway runtime image not found; build via Dockerfile.gateway' >&2
  exit 2
}
args=(python3 -m arvectum_compliance.service.egress_worker "$mode")
if [[ -n "$fixture" ]]; then args+=("$fixture"); fi
exec docker run --rm -i \
  --network bridge --dns 1.1.1.1 \
  --cap-drop ALL --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
  --security-opt no-new-privileges:true \
  --read-only --pids-limit 64 --memory 320m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m \
  "$image" "${args[@]}"
