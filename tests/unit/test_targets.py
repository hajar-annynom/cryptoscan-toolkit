import pytest

from cryptoscan.parsers.target_parser import expand_hosts, parse_ports


def test_parse_ports_lists_and_ranges():
    assert parse_ports("22,443,8000-8002") == [22, 443, 8000, 8001, 8002]


def test_parse_ports_dedupes():
    assert parse_ports("443,443") == [443]


@pytest.mark.parametrize("bad", ["0", "70000", "abc", "10-5", ""])
def test_parse_ports_rejects_garbage(bad):
    with pytest.raises(ValueError):
        parse_ports(bad)


def test_expand_cidr_skips_network_and_broadcast():
    assert expand_hosts(["10.0.0.0/30"]) == ["10.0.0.1", "10.0.0.2"]


def test_expand_plain_hosts_passthrough():
    assert expand_hosts(["example.com", "10.0.0.5"]) == ["example.com", "10.0.0.5"]


def test_expand_refuses_huge_ranges():
    with pytest.raises(ValueError):
        expand_hosts(["10.0.0.0/8"])
