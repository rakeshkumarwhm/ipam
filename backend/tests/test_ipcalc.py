import pytest

from app import ipcalc


def test_usable_and_free():
    n = ipcalc.parse_network("10.0.0.0/29")
    assert ipcalc.usable_count(n) == 6
    assert ipcalc.next_free(n, {"10.0.0.1", "10.0.0.2"}) == "10.0.0.3"
    assert not ipcalc.is_usable(n, ipcalc.parse_ip("10.0.0.7"))


def test_host_bits_rejected():
    with pytest.raises(ValueError):
        ipcalc.parse_network("10.0.0.1/24")


def test_ipv6():
    n = ipcalc.parse_network("2001:db8::/64")
    assert ipcalc.next_free(n, {"2001:db8::"}) == "2001:db8::1"
