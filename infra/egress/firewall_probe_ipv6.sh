#!/bin/sh
set -eu
[ "$(id -u)" = 65532 ] || exit 30
cap_eff="$(awk '/^CapEff:/ {print $2}' /proc/self/status)"
cap_bnd="$(awk '/^CapBnd:/ {print $2}' /proc/self/status)"
[ "$cap_eff:$cap_bnd" = '0000000000000000:0000000000000000' ] || exit 31
nc -l -p 443 -s ::1 >/dev/null 2>&1 &
pid="$!"
trap 'kill "$pid" 2>/dev/null || true' EXIT
sleep 0.3
kill -0 "$pid" 2>/dev/null || exit 32
netstat -lnt | grep -q '::1:443 ' || exit 33
if nc -n -z -w 2 ::1 443 >/dev/null 2>&1; then
  echo 'IPV6_LOOPBACK_443_REACHABLE' >&2
  exit 35
fi
printf '%s\n' '{"ipv6_loopback":"unreachable","uid":65532,"caps_zero":true}'
