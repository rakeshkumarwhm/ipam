"""CIDR helpers built on the standard library `ipaddress` module."""
import ipaddress
from ipaddress import IPv4Network, IPv6Network

Network = IPv4Network | IPv6Network


def parse_network(cidr: str) -> Network:
    """Parse and normalise a network; host bits must be zero."""
    try:
        return ipaddress.ip_network(cidr.strip(), strict=True)
    except ValueError as e:
        raise ValueError(f"Invalid network: {e}") from None


def parse_ip(value: str):
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        raise ValueError("Invalid IP address") from None


def usable_count(net: Network) -> int:
    n = net.num_addresses
    if net.version == 4 and net.prefixlen <= 30:
        return n - 2  # network + broadcast
    return n


def is_usable(net: Network, ip) -> bool:
    if ip not in net:
        return False
    if net.version == 4 and net.prefixlen <= 30:
        return ip != net.network_address and ip != net.broadcast_address
    return True


def next_free(net: Network, used: set[str], limit: int = 100000) -> str | None:
    """First free usable address, examining at most `limit` candidates."""
    if net.version == 4 and net.prefixlen <= 30:
        candidates = net.hosts()
    else:
        candidates = (net[i] for i in range(min(net.num_addresses, limit)))
    for i, host in enumerate(candidates):
        if i >= limit:
            return None
        if str(host) not in used:
            return str(host)
    return None


def overlaps(a: Network, b: Network) -> bool:
    return a.version == b.version and a.overlaps(b)
