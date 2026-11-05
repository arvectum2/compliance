#!/bin/sh
# Rules are installed with CAP_NET_ADMIN, then ALL capabilities are dropped.
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'FIREWALL_ERROR: startup must run as init root' >&2
  exit 30
fi
nft -c -f /etc/compliance-egress.nft || {
  echo 'FIREWALL_ERROR: rules invalid' >&2
  exit 31
}
nft -f /etc/compliance-egress.nft || {
  echo 'FIREWALL_ERROR: nft install failed' >&2
  exit 32
}
nft list table inet compliance_egress >/dev/null || {
  echo 'FIREWALL_ERROR: policy missing' >&2
  exit 33
}
echo 'FIREWALL_APPLIED'
exec setpriv --reuid 65532 --regid 65532 --clear-groups \
  --bounding-set=-all --inh-caps=-all --ambient-caps=-all "$@"
