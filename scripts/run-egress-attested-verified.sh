#!/usr/bin/env bash
# No URL, host, DNS bypass, fake proof or private key is accepted by this
# launcher. The hostname comes ONLY from an Ed25519-verified lease.
set -euo pipefail
if [[ "$#" -ne 0 ]]; then echo 'No target arguments accepted' >&2; exit 2; fi
pub="${COMPLIANCE_ATTEST_PUBLIC_KEY_FILE:-}"
if [[ -z "$pub" || ! -f "$pub" || -L "$pub" ]]; then
  echo 'Missing regular public key file' >&2; exit 2
fi
if [[ "$(wc -c < "$pub" | tr -d ' ')" != '32' ]]; then
  echo 'Wrong public key size' >&2; exit 2
fi
image='arvectum/compliance-egress-runtime:eg003b'
docker image inspect "$image" >/dev/null 2>&1 || {
  echo 'Build gateway Dockerfile.gateway first' >&2; exit 2
}
exec docker run --rm -i \
  --network bridge --dns 1.1.1.1 \
  --cap-drop ALL --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
  --security-opt no-new-privileges:true \
  --read-only --pids-limit 64 --memory 320m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m \
  --mount "type=bind,source=$pub,target=/run/compliance/attestor.pub,readonly" \
  "$image" python3 -m arvectum_compliance.service.egress_worker attested-verified
