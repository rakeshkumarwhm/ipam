"""ICMP subnet scanner. Uses the system `ping` binary with an argument list (no shell)."""
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor

from .ipcalc import Network


def _ping(ip: str) -> bool:
    exe = shutil.which("ping")
    if exe is None:
        raise RuntimeError("ping binary not found")
    try:
        # ip comes from the ipaddress module, never from raw user input.
        r = subprocess.run([exe, "-c", "1", "-W", "1", ip], capture_output=True,
                           timeout=5, check=False)  # nosec B603
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def scan(net: Network, max_hosts: int, workers: int) -> dict[str, bool]:
    if net.num_addresses > max_hosts + 2:
        raise ValueError(f"Subnet too large to scan (max {max_hosts} hosts)")
    hosts = [str(h) for h in net.hosts()]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return dict(zip(hosts, pool.map(_ping, hosts)))
