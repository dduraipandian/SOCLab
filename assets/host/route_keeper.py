"""Keep the host's default route on egress-gw without spawning a process every second.

Reads /proc/net/route once a second and runs `ip route replace` only when the route is actually wrong (at
start, and after containment release reconnects corp-net). Standard library only.
"""

import os
import socket
import subprocess
import time

CORP_NET_HEX = "0000140A"  # 10.20.0.0, little-endian as in /proc/net/route


def _hex_le(ip: str) -> str:
    return socket.inet_aton(ip)[::-1].hex().upper()


def needs_fix(route_text: str, gateway: str) -> bool:
    rows = [line.split() for line in route_text.splitlines()[1:] if line.strip()]
    corp_attached = any(r[1] == CORP_NET_HEX for r in rows)
    defaults = [r[2] for r in rows if r[1] == "00000000"]
    return corp_attached and _hex_le(gateway) not in defaults


def main() -> None:
    gateway = os.environ["EGRESS_GW_IP"]
    while True:
        try:
            with open("/proc/net/route") as f:
                if needs_fix(f.read(), gateway):
                    subprocess.run(["ip", "route", "replace", "default", "via", gateway],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        except OSError:
            pass
        time.sleep(1)


if __name__ == "__main__":
    main()
