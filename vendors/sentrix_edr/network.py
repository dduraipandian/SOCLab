"""Host network isolation. Containment disconnects the host from corp-net; mgmt-<host> stays up."""

from typing import Protocol


class UnmanagedHost(Exception):
    """The container is not one of the lab hosts this EDR manages."""


class NetworkController(Protocol):
    def isolate(self, host: str) -> None: ...
    def restore(self, host: str) -> None: ...


class FakeNetworkController:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def isolate(self, host: str) -> None:
        self.calls.append(("isolate", host))

    def restore(self, host: str) -> None:
        self.calls.append(("restore", host))


class DockerNetworkController:
    """Disconnects/reconnects a host container on corp-net, keeping its fixed IP on reconnect."""

    def __init__(self, client, network: str, host_ips: dict[str, str]) -> None:
        self.client = client
        self.network = network
        self.host_ips = host_ips

    def _check(self, host: str) -> None:
        if host not in self.host_ips:
            raise UnmanagedHost(host)

    def isolate(self, host: str) -> None:
        self._check(host)
        net = self.client.networks.get(self.network)
        if host in self._attached(net):
            net.disconnect(host, force=True)

    def restore(self, host: str) -> None:
        self._check(host)
        net = self.client.networks.get(self.network)
        if host not in self._attached(net):
            net.connect(host, ipv4_address=self.host_ips[host])

    @staticmethod
    def _attached(net) -> set[str]:
        net.reload()
        return {c.name for c in net.containers}


def parse_host_ips(spec: str) -> dict[str, str]:
    """'fin-laptop-07=10.20.0.11,eng-ws-03=10.20.0.12' -> {host: ip}."""
    pairs = (p.split("=", 1) for p in spec.split(",") if "=" in p)
    return {h.strip(): ip.strip() for h, ip in pairs}
