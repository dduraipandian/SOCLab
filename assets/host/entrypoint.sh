#!/bin/bash
# Host container entrypoint: sensor daemon first (so it sees everything), default route via egress-gw,
# a TCP listener on port 7 for reachability probes, then cron.
set -u
mkdir -p /run/sensor
if [ "${SENSOR_DISABLED:-0}" != "1" ]; then
  # Supervised: if the daemon ever exits, restart it after a second.
  ( while true; do PYTHONPATH=/opt/sensor python3 -m sensor.daemon >> /var/log/sensor.log 2>&1; sleep 1; done ) &
  for _ in $(seq 50); do [ -S /run/sensor/hook.sock ] && break; sleep 0.1; done
fi

if [ -n "${EGRESS_GW_IP:-}" ]; then
  # Keep the default route on egress-gw; re-applied after containment release reconnects corp-net.
  python3 /opt/route_keeper.py > /dev/null 2>&1 &
fi

python3 -c "
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 7)); s.listen(64)
while True:
    c, _ = s.accept(); c.close()
" > /dev/null 2>&1 &

if [ "$(hostname)" = "build-01" ]; then
  # S6: the legitimate nightly password-expiry audit, scheduled daily at 02:00.
  echo '0 2 * * * svc-maint /bin/bash /opt/maint/nightly.sh' > /etc/cron.d/nightly-maint
  chmod 644 /etc/cron.d/nightly-maint
fi

service cron start > /dev/null 2>&1 || cron
exec sleep infinity
