#!/usr/bin/env bash
# Offline Chromium in a Linux network namespace with no egress.
set -euo pipefail
repo="$(CDPATH='' cd "$(dirname "$0")/.." && pwd)"
fixture="${1:-}"
case "$fixture" in
  consent.html|attack.html|inconclusive.html) ;;
  *) echo 'Expected one approved HTML fixture: consent.html | attack.html | inconclusive.html' >&2; exit 2 ;;
esac
if [[ "$#" -ne 1 ]]; then
  echo 'Only one positional fixture argument is supported' >&2
  exit 2
fi
image='mcr.microsoft.com/playwright@sha256:2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f'
# Never pull an image implicitly inside a test, never open a host port.
docker image inspect "$image" >/dev/null 2>&1 || {
  echo "Docker image not installed: $image" >&2
  exit 2
}
test -d "$repo/browser-worker/node_modules/playwright" || {
  echo 'Run npm ci --prefix browser-worker --ignore-scripts first' >&2
  exit 2
}
docker run --rm \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --read-only --pids-limit 180 --memory 1200m --cpus 2 \
  --shm-size 256m --tmpfs /tmp:rw,nosuid,nodev,size=256m \
  --user pwuser \
  --mount "type=bind,source=$repo/browser-worker,target=/app,readonly" \
  --mount "type=bind,source=$repo/tests/browser-fixtures,target=/fixtures,readonly" \
  --workdir /app \
  --env PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
  --entrypoint node "$image" worker.mjs "$fixture"
