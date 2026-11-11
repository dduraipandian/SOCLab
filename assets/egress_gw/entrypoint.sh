#!/bin/bash
# Router between corp-net and internet-net: forwards and NATs host traffic out to the "internet".
set -euo pipefail
OUT_IF=$(ip -o -4 addr show | awk '$4 ~ /^203\.0\.113\./ {print $2; exit}')
iptables -t nat -A POSTROUTING -o "$OUT_IF" -j MASQUERADE
iptables -A FORWARD -j ACCEPT
echo "egress-gw: forwarding via $OUT_IF"
exec sleep infinity
