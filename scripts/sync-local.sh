#!/bin/zsh
# Safe GitHub -> Mac mini fast-forward on the clean main branch only.
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
repo=/Volumes/ArvectumSSD/Arvectum/repos/compliance
if [[ ! -d "$repo/.git" ]]; then
  echo "SKIP: volume or checkout unavailable"
  exit 0
fi
cd "$repo"
branch="$(git branch --show-current)"
if [[ "$branch" != main ]]; then
  echo "SKIP: active branch ${branch:-detached}"
  exit 0
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo "SKIP: uncommitted changes"
  exit 0
fi
git fetch --quiet origin main
git merge --ff-only --quiet origin/main
echo "OK: $(git rev-parse --short HEAD)"
