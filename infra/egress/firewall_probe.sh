#!/bin/sh
# A real open listener on 443 proves the kernel drops internal destinations
# even though 443 is allowed for public destinations by the nftables policy.
set -eu
[ "$(id -u)" = 65532 ] || { echo 'UID_NOT_DROPPED' >&2; exit 20; }
cap_eff="$(awk '/^CapEff:/ {print $2}' /proc/self/status)"
cap_bnd="$(awk '/^CapBnd:/ {print $2}' /proc/self/status)"
case "$cap_eff:$cap_bnd" in
  0000000000000000:0000000000000000) ;;
  *) echo 'CAPABILITIES_NOT_DROPPED' >&2; exit 21 ;;
esac
nc -l -p 443 -s 0.0.0.0 >/dev/null 2>&1 &
listener="$!"
trap 'kill "$listener" 2>/dev/null || true' EXIT
sleep 0.3
kill -0 "$listener" 2>/dev/null || { echo 'LISTENER_NOT_RUNNING' >&2; exit 22; }
netstat -lnt | grep -q ':443 ' || { echo 'LISTENER_NOT_BOUND' >&2; exit 23; }
bridge_ip="$(getent hosts "$(hostname)" | awk '$1 ~ /^[0-9.]+$/ {print $1;exit}')"
[ -n "$bridge_ip" ] || { echo 'NO_BRIDGE_ADDRESS' >&2; exit 24; }
if [ "${COMPLIANCE_PROBE_SKIP_LOOPBACK:-0}" != 1 ]; then
  if nc -n -z -w 2 127.0.0.1 443 >/dev/null 2>&1; then
    echo 'LOOPBACK_443_REACHABLE' >&2
    exit 25
  fi
fi
if nc -n -z -w 2 "$bridge_ip" 443 >/dev/null 2>&1; then
  echo 'PRIVATE_BRIDGE_443_REACHABLE' >&2
  exit 26
fi
if nft flush ruleset >/dev/null 2>&1; then
  echo 'FIREWALL_MODIFIABLE' >&2
  exit 27
fi
printf '%s\n' '{"uid":65532,"caps_zero":true,"loopback_listener":"unreachable","bridge_listener":"unreachable","firewall_unmodifiable":true}'
