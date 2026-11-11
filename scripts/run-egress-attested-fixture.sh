#!/usr/bin/env bash
# Test-only signed IPC runtime. Browser cannot choose host or public key.
set -euo pipefail
repo="$(CDPATH='' cd "$(dirname "$0")/.." && pwd)"
if [[ "$#" -ne 1 ]]; then echo 'Expected one fixture' >&2; exit 2; fi
case "$1" in
  consent.html|attack.html|inconclusive.html|security.html) ;;
  *) echo 'Only synthetic fixture names accepted' >&2; exit 2 ;;
esac
pub="${COMPLIANCE_ATTEST_PUBLIC_KEY_FILE:-}"
if [[ -z "$pub" || ! -f "$pub" || -L "$pub" ]]; then
  echo 'Missing regular public key file' >&2; exit 2
fi
size="$(wc -c < "$pub" | tr -d ' ')"
if [[ "$size" != '32' ]]; then echo 'Wrong public key size' >&2; exit 2; fi
image='arvectum/compliance-egress-runtime:eg003b'
docker image inspect "$image" >/dev/null 2>&1 || {
  echo 'Build the gateway image first' >&2; exit 2
}
exec docker run --rm -i \
  --network bridge --dns 1.1.1.1 \
  --cap-drop ALL --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
  --security-opt no-new-privileges:true \
  --read-only --pids-limit 64 --memory 320m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m \
  --mount "type=bind,source=$pub,target=/run/compliance/attestor.pub,readonly" \
  "$image" python3 -m arvectum_compliance.service.egress_worker attested-fixture "$1"
