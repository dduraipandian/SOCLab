#!/bin/bash
# Router between corp-net and internet-net: forwards and NATs host traffic out to the "internet".
set -euo pipefail
OUT_IF=$(ip -o -4 addr show | awk '$4 ~ /^203\.0\.113\./ {print $2; exit}')
iptables -t nat -A POSTROUTING -o "$OUT_IF" -j MASQUERADE
# Forward only into the fake internet, plus its replies. Anything else (a real public address, which this
# container's default route would send to corp-net's Docker gateway and the real internet) is dropped.
iptables -P FORWARD DROP
iptables -A FORWARD -o "$OUT_IF" -j ACCEPT
iptables -A FORWARD -i "$OUT_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
echo "egress-gw: forwarding via $OUT_IF"
exec sleep infinity
