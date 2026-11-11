from assets.host.route_keeper import needs_fix

# /proc/net/route columns: Iface Destination Gateway Flags ... (little-endian hex)
HEADER = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
CORP = "eth0\t0000140A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
DEFAULT_VIA_GW = "eth0\t00000000\t0200140A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
DEFAULT_VIA_DOCKER = "eth0\t00000000\t0100140A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"


def test_no_fix_when_default_route_is_the_gateway():
    assert needs_fix(HEADER + CORP + DEFAULT_VIA_GW, "10.20.0.2") is False


def test_fix_when_default_route_points_elsewhere():
    assert needs_fix(HEADER + CORP + DEFAULT_VIA_DOCKER, "10.20.0.2") is True


def test_fix_when_default_route_missing_but_corp_net_attached():
    assert needs_fix(HEADER + CORP, "10.20.0.2") is True


def test_no_fix_while_contained():
    assert needs_fix(HEADER, "10.20.0.2") is False
