#!/usr/bin/env bash
# Offline browser; gateway replies are passed over process stdin, NEVER a socket.
set -euo pipefail
repo="$(CDPATH='' cd "$(dirname "$0")/.." && pwd)"
if [[ "$#" -ne 1 ]]; then
  echo 'Expected one explicit fixture argument' >&2
  exit 2
fi
case "$1" in
  consent.html|attack.html|inconclusive.html|internal-owned) ;;
  *) echo 'Only approved synthetic fixtures are supported' >&2; exit 2 ;;
esac
image='mcr.microsoft.com/playwright@sha256:2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f'
docker image inspect "$image" >/dev/null 2>&1 || {
  echo 'Pinned browser image is not installed' >&2
  exit 2
}
test -d "$repo/browser-worker/node_modules/playwright" || {
  echo 'Run npm ci --prefix browser-worker first' >&2
  exit 2
}
exec docker run --rm -i \
  --network none --cap-drop ALL --security-opt no-new-privileges:true \
  --read-only --pids-limit 180 --memory 1200m --cpus 2 \
  --shm-size 256m --tmpfs /tmp:rw,nosuid,nodev,size=256m \
  --user pwuser \
  --mount "type=bind,source=$repo/browser-worker,target=/app,readonly" \
  --workdir /app --env PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
  --entrypoint node "$image" bridge_worker.mjs "$1"
