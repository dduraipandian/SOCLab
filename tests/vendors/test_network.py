import pytest

from vendors.sentrix_edr.network import DockerNetworkController, UnmanagedHost


class FakeNet:
    def __init__(self):
        self.calls, self.containers = [], []

    def reload(self):
        pass

    def connect(self, name, ipv4_address=None):
        self.calls.append(("connect", name, ipv4_address))

    def disconnect(self, name, force=False):
        self.calls.append(("disconnect", name))


class FakeClient:
    def __init__(self, net):
        self.networks = type("N", (), {"get": lambda _self, _name: net})()


def test_controller_refuses_hosts_it_does_not_manage():
    net = FakeNet()
    ctl = DockerNetworkController(FakeClient(net), "corp-net", {"fin-laptop-07": "10.20.0.11"})
    for op in (ctl.isolate, ctl.restore):
        with pytest.raises(UnmanagedHost):
            op("soc-lab-postgres-1")
    assert net.calls == []


def test_controller_restores_with_fixed_ip():
    net = FakeNet()
    DockerNetworkController(FakeClient(net), "corp-net", {"fin-laptop-07": "10.20.0.11"}).restore("fin-laptop-07")
    assert net.calls == [("connect", "fin-laptop-07", "10.20.0.11")]
