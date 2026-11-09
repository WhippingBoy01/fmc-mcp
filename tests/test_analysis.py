from fmc_mcp.analysis import endpoint_overlaps, parse_endpoint, parse_port, port_matches


def test_parse_endpoint_ip_cidr_range_fqdn():
    assert parse_endpoint("10.0.0.1").kind == "ipv4"
    assert parse_endpoint("10.0.0.0/24").kind == "network"
    assert parse_endpoint("10.0.0.1-10.0.0.10").kind == "range"
    assert parse_endpoint("app.example.com").kind == "fqdn"
    assert parse_endpoint("any").kind == "any"


def test_endpoint_overlap():
    ok, _ = endpoint_overlaps(parse_endpoint("10.0.0.5"), "10.0.0.0/24")
    assert ok
    ok, _ = endpoint_overlaps(parse_endpoint("10.0.1.5"), "10.0.0.0/24")
    assert not ok
    ok, _ = endpoint_overlaps(parse_endpoint("app.example.com"), "app.example.com")
    assert ok


def test_port_parsing_and_match():
    assert parse_port("443") == (443, 443, "443")
    assert parse_port("80-90")[0:2] == (80, 90)
    ok, _ = port_matches(443, "TCP", {"protocol": "TCP", "port": "443"})
    assert ok is True
    ok, _ = port_matches(443, "TCP", {"protocol": "TCP", "port": "80"})
    assert ok is False
