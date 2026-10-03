
from __future__ import annotations

import ctypes
import ipaddress
import logging
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .models import normalize_mac_address, oui_prefix

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Adapter classification
# ---------------------------------------------------------------------------

#: Name fragments identifying a virtual tunnel / VM / container interface.
VIRTUAL_ADAPTER_HINTS: tuple[str, ...] = (
    "tap", "tun", "wintun", "wireguard", "openvpn", "nordlynx", "nordtun",
    "tailscale", "zerotier", "radmin", "hamachi", "virtualbox", "vmware",
    "hyper-v", "vethernet", "loopback", "bluetooth", "virtual", "vmxnet",
    "docker", "wsl", "vpn", "anyconnect", "globalprotect", "forticlient",
    "juniper", "nordvpn", "expressvpn", "protonvpn", "mullvad", "clash",
    "v2ray", "xray", "sing-box", "teredo", "isatap", "6to4", "pseudo-interface",
)

#: Physical NIC markers. These take precedence over the virtual hints.
PHYSICAL_ADAPTER_HINTS: tuple[str, ...] = (
    "wi-fi", "wifi", "wireless", "wlan", "ethernet", "realtek", "intel",
    "broadcom", "killer", "atheros",
)

#: Executables that indicate a running VPN or proxy client.
VPN_PROCESS_HINTS: tuple[str, ...] = (
    "openvpn", "wireguard", "tailscale", "zerotier", "nordvpn", "expressvpn",
    "protonvpn", "mullvad", "radmin", "anyconnect", "forticlient",
    "globalprotect", "psiphon", "windscribe", "surfshark", "clash", "v2ray",
    "xray", "sing-box", "opera",
)

#: Helper binaries that inherit the product name but are not VPNs.
VPN_PROCESS_NOISE: tuple[str, ...] = ("crashreporter", "crash handler", "updater")

#: Local ports commonly used by proxies, tunnels and browser extensions.
LOCAL_PROXY_PORTS: dict[int, str] = {
    1080: "SOCKS", 1081: "SOCKS", 3128: "Squid", 7890: "Clash",
    7891: "Clash", 8080: "HTTP proxy", 8118: "Privoxy", 8888: "HTTP proxy",
    9050: "Tor SOCKS", 10808: "V2Ray", 10809: "V2Ray",
}


def is_virtual_adapter(name: str) -> bool:
    """Classify a local adapter name as virtual (VPN/tunnel/VM) or physical."""
    lowered = name.lower()
    if any(hint in lowered for hint in PHYSICAL_ADAPTER_HINTS):
        return False
    return any(hint in lowered for hint in VIRTUAL_ADAPTER_HINTS)


@dataclass(frozen=True)
class NetworkAdapter:
    """
    One local network interface, as offered by the interface selector.

    ``network`` is the CIDR the adapter itself sits on, which is what a scan
    of that interface should cover. An adapter without a usable IPv4 (loopback,
    Teredo, a down NIC) reports an empty one and is never scannable.
    """

    name: str
    address: str = ""
    netmask: str = ""
    network: str = ""
    is_virtual: bool = False
    is_up: bool = True

    @property
    def is_scannable(self) -> bool:
        """
        True when this adapter can host a sweep of its own subnet.

        A link-local address looks private to :mod:`ipaddress` but describes
        an autoconfiguration segment nobody routes to, so it is rejected here
        exactly as :func:`_is_sweepable` rejects it: the selector must never
        offer a range the scanner would refuse to suggest.

        Being outside RFC 1918 does not disqualify an adapter, which is what
        lets a VPN overlay be scanned like any other. Its range is clamped by
        :func:`clamp_to_sweep`, so a virtual adapter advertising a /8 still
        offers something a sweep can actually finish.
        """
        return (bool(self.network) and self.is_up
                and not self.is_loopback and not self.is_link_local)

    @property
    def sweep_range(self) -> str:
        """The range to sweep for this adapter, clamped to a sweepable size."""
        if not self.network or not self.is_scannable:
            return ""
        try:
            return clamp_to_sweep(
                ipaddress.ip_network(self.network, strict=False))
        except ValueError:
            return ""

    @property
    def is_loopback(self) -> bool:
        """True for 127.0.0.0/8, which can never host a useful sweep."""
        return self.address.startswith("127.")

    @property
    def is_link_local(self) -> bool:
        """True for 169.254.0.0/16, an autoconfiguration fallback range."""
        return self.address.startswith("169.254.")

    @property
    def label(self) -> str:
        """Compact one-line description for the dropdown."""
        if not self.address:
            return self.name
        return f"{self.name}  ·  {self.network or self.address}"


def _interface_name(raw: object) -> str:
    """psutil returns bytes on some platforms and text on others."""
    return (raw.decode("utf-8", "ignore") if isinstance(raw, bytes)
            else str(raw))


def list_adapters() -> list[NetworkAdapter]:
    """
    Enumerate local IPv4 interfaces, the most useful one first.

    Ordering matters because the first entry seeds the suggested scan range:
    an active physical adapter beats a link-local fallback, which in turn
    beats a VPN overlay, because sweeping the wrong one is the exact problem
    the selector exists to solve.
    """
    import psutil

    adapters: list[NetworkAdapter] = []
    try:
        addresses = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except Exception:  # noqa: BLE001 - psutil missing or restricted
        return adapters

    for raw_name, interface in addresses.items():
        name = _interface_name(raw_name)
        is_up = bool(getattr(stats.get(raw_name), "isup", True))

        for entry in interface:
            if entry.family != socket.AF_INET or not entry.address:
                continue
            try:
                network = ipaddress.ip_network(
                    f"{entry.address}/{entry.netmask}", strict=False)
            except (ValueError, TypeError):
                continue
            adapters.append(NetworkAdapter(
                name=name,
                address=entry.address,
                netmask=entry.netmask or "",
                network=str(network) if network.num_addresses > 1 else "",
                is_virtual=is_virtual_adapter(name),
                is_up=is_up,
            ))
            break

    adapters.sort(key=lambda adapter: (
        not adapter.is_scannable and not adapter.is_link_local,
        adapter.is_link_local,
        adapter.is_virtual,
        not adapter.is_up,
    ))
    return adapters


def find_adapter(name: str) -> NetworkAdapter | None:
    """Look one adapter up by its exact name, or ``None`` when it is gone."""
    return next((a for a in list_adapters() if a.name == name), None)


# ---------------------------------------------------------------------------
# Privilege / capability probing
# ---------------------------------------------------------------------------

def is_elevated() -> bool:
    """True when the process can open raw sockets (root, or admin on Windows)."""
    if hasattr(os, "geteuid"):          # POSIX
        return os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - non-Windows without ctypes
        return False


def supports_layer2() -> bool:
    """True when scapy can open a layer-2 socket (requires Npcap/WinPcap)."""
    try:
        from scapy.all import conf
    except ImportError:
        return False
    try:
        layer2_socket = conf.L2socket()
    except Exception:  # noqa: BLE001 - driver missing or permission denied
        return False
    try:
        layer2_socket.close()
    except Exception:  # noqa: BLE001
        pass
    return True
# ---------------------------------------------------------------------------
# Vendor (OUI) resolution
# ---------------------------------------------------------------------------

_VENDOR_TABLE: dict[str, str] = {}


def _vendor_cache_paths() -> list[Path]:
    """
    Candidate locations of the on-disk OUI list.

    The library searches several roots depending on how it was installed
    (user home, ``sys.prefix``, or relative to its own package), so we ask
    it first and only then fall back to the known virtualenv layouts.
    """
    import sys

    import mac_vendor_lookup

    candidates: list[Path] = []
    located = mac_vendor_lookup.MacLookup().find_vendors_list()
    if located:
        candidates.append(Path(located))

    candidates.append(Path(sys.prefix) / "cache" / "mac-vendors.txt")
    candidates.append(
        Path(mac_vendor_lookup.__file__).resolve().parent.parent
        / "cache"
        / "mac-vendors.txt"
    )
    return candidates

def load_vendor_table() -> dict[str, str]:
    """
    Return the ``{OUI prefix: vendor}`` table, fetching it on first use.

    ``mac-vendor-lookup`` ships no database: it downloads the IEEE list and
    caches it on disk as ``PREFIX:Vendor`` records. We download once, parse
    once and serve every lookup from memory.
    """
    global _VENDOR_TABLE
    if _VENDOR_TABLE:
        return _VENDOR_TABLE

    try:
        import mac_vendor_lookup
    except ImportError:
        return {}

    candidates = _vendor_cache_paths()
    if not any(path.is_file() for path in candidates):
        try:
            mac_vendor_lookup.MacLookup().update_vendors()
        except Exception:  # noqa: BLE001 - offline: vendors stay unknown
            logger.warning("Could not download the OUI list", exc_info=True)
            return {}

    for path in candidates:
        if not path.is_file():
            continue
        table: dict[str, str] = {}
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            prefix, separator, vendor = line.partition(":")
            if separator and len(prefix) == 6 and vendor.strip():
                table[prefix.strip().upper()] = vendor.strip()
        _VENDOR_TABLE = table
        break

    logger.info("Loaded %d OUI vendor entries", len(_VENDOR_TABLE))
    return _VENDOR_TABLE


def lookup_vendor(mac_address: str | None) -> str:
    """Return the vendor registered for a MAC, or "" when unresolvable."""
    prefix = oui_prefix(mac_address)
    if prefix is None:
        return ""
    # The IEEE list keys entries as six bare hex digits, no separators.
    return load_vendor_table().get(prefix.replace(":", ""), "")


# ---------------------------------------------------------------------------
# ARP (layer 2) helpers
# ---------------------------------------------------------------------------

def read_arp_cache() -> dict[str, str]:
    """Parse the OS neighbour table (``arp -a``) into ``{ip: mac}``.

    Requires no drivers and no elevated rights, so it is the fallback used
    whenever scapy cannot open a layer-2 socket.
    """
    import re
    import subprocess

    pattern = re.compile(
        r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+"
        r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})"
    )
    # The neighbour table is printed by the console, in the OEM code page, and
    # its header is translated ("Interfaz" / "Estadisticas" carry accents).
    # Without an explicit encoding the child is decoded as UTF-8 and a
    # Spanish Windows raises UnicodeDecodeError inside the reader thread,
    # which kills the whole discovery phase. Reusing the ping module's code
    # page keeps the two shell-outs reading the same bytes the same way.
    from .ping import console_encoding

    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=10,
            encoding=console_encoding(),
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return {}

    entries: dict[str, str] = {}
    for line in result.stdout.splitlines():
        match = pattern.match(line)
        if match:
            ip_text, mac_text = match.groups()
            normalized = normalize_mac_address(mac_text)
            if normalized:
                entries[ip_text] = normalized
    return entries


# ---------------------------------------------------------------------------
# Local topology
# ---------------------------------------------------------------------------

def iter_local_ipv4(interface: str = "") -> list[tuple[str, str]]:
    """
    Return ``(ip, netmask)`` for every IPv4 address bound locally.

    ``interface`` narrows the result to one adapter, which is how a scan
    stays on the NIC the operator picked instead of every one the machine
    happens to own.
    """
    import psutil

    addresses: list[tuple[str, str]] = []
    for raw_name, entries in psutil.net_if_addrs().items():
        if interface and _interface_name(raw_name) != interface:
            continue
        for address in entries:
            if address.family == socket.AF_INET and address.address and address.netmask:
                addresses.append((address.address, address.netmask))
    return addresses


def is_ip_in_virtual_subnet(ip: str) -> bool:
    """True when the IP falls inside a virtual adapter's subnet."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False

    import psutil

    for raw_name, interface in psutil.net_if_addrs().items():
        name = (
            raw_name.decode("utf-8", "ignore")
            if isinstance(raw_name, bytes)
            else str(raw_name)
        )
        if not is_virtual_adapter(name):
            continue
        for address_info in interface:
            if address_info.family != socket.AF_INET or not address_info.netmask:
                continue
            try:
                subnet = ipaddress.ip_network(
                    f"{address_info.address}/{address_info.netmask}", strict=False
                )
            except ValueError:
                continue
            if address.version == subnet.version and address in subnet:
                return True
    return False


#: Seconds a parsed routing table is reused. Every adapter change re-reads the
#: gateway, and spawning ``route print`` each time is a 150 ms stall for an
#: answer that cannot change that quickly.
_ROUTE_CACHE_SECONDS = 5.0
_route_cache: tuple[float, list[tuple[str, str]]] = (0.0, [])


def _route_gateways() -> list[tuple[str, str]]:
    """
    Every IPv4 default route on the box as ``(gateway, source_address)``.

    Reading the routing table is the only portable way to learn the gateway;
    :mod:`psutil` lists addresses but not routes. A machine with a VPN, a
    Hyper-V bridge and a dock has several default routes, so all of them come
    back and the caller decides which one belongs to the operator.
    """
    global _route_cache
    stamp, cached = _route_cache
    now = time.monotonic()
    if cached and now - stamp < _ROUTE_CACHE_SECONDS:
        return cached

    routes = _read_route_table()
    _route_cache = (now, routes)
    return routes


def _read_route_table() -> list[tuple[str, str]]:
    if sys.platform == "win32":
        try:
            output = subprocess.run(
                ["route", "print", "-4"], capture_output=True, text=True,
                timeout=5, encoding="utf-8", errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return []
        rows: list[tuple[str, str]] = []
        for line in output.splitlines():
            fields = line.split()
            # Network Destination, Netmask, Gateway, Interface, Metric.
            if len(fields) >= 4 and fields[0] == "0.0.0.0" and fields[1] == "0.0.0.0":
                gateway, source = fields[2], fields[3]
                if gateway != "0.0.0.0" and _is_ipv4(gateway) and _is_ipv4(source):
                    rows.append((gateway, source))
        return rows

    if sys.platform.startswith("linux"):
        try:
            text = Path("/proc/net/route").read_text(encoding="utf-8")
        except OSError:
            return []
        rows = []
        for line in text.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 3 or fields[1] != "00000000":
                continue
            try:
                # The kernel prints the gateway as a packed little-endian word.
                packed = int(fields[2], 16).to_bytes(4, "little")
                rows.append((socket.inet_ntoa(packed), ""))
            except (ValueError, OSError):
                continue
        return rows

    try:
        output = subprocess.run(
            ["netstat", "-nr", "-f", "inet"], capture_output=True, text=True,
            timeout=5, encoding="utf-8", errors="replace",
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    rows = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "default" and _is_ipv4(fields[1]):
            rows.append((fields[1], ""))
    return rows


def _is_ipv4(text: str) -> bool:
    """True when ``text`` parses as an IPv4 address."""
    try:
        ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return True


def default_gateway(interface: str = "") -> str:
    """
    The IPv4 default gateway for ``interface``, or for the machine at large.

    A VPN adds its own default route, and a technician plugged into a dock
    wants the one on that cable, not the tunnel. So the chosen adapter's own
    addresses decide; failing that, any route whose source sits on a real
    local network wins over one with no source at all.
    """
    routes = _route_gateways()
    if not routes:
        return ""

    networks = []
    for ip_text, netmask in iter_local_ipv4(interface):
        try:
            network = ipaddress.ip_network(f"{ip_text}/{netmask}", strict=False)
        except ValueError:
            continue
        if _is_sweepable(network):
            networks.append(network)

    def belongs(source: str) -> bool:
        if not source:
            return False
        try:
            address = ipaddress.ip_address(source)
        except ValueError:
            return False
        return any(address in network for network in networks)

    for gateway, source in routes:
        if belongs(source):
            return gateway
    return routes[0][0]


def local_network_hint(interface: str = "") -> str:
    """
    Return a CIDR for the network the operator is really sitting on.

    The default gateway is the anchor: the local network that owns it is the
    user's own LAN, which is not always the smallest one on the box. A VPN
    handing out a /8 and a virtual switch handing out a /30 both lose to the
    /24 behind the router.

    Without a usable gateway the smallest scannable network is offered, and
    an oversized one is clamped to a /16 so the suggestion stays a sweep
    rather than a mistake.
    """
    networks: list[ipaddress.IPv4Network] = []
    for ip_text, netmask in iter_local_ipv4(interface):
        try:
            network = ipaddress.ip_network(f"{ip_text}/{netmask}", strict=False)
        except ValueError:
            continue
        if _is_sweepable(network):
            networks.append(network)

    gateway = default_gateway(interface)
    if gateway:
        try:
            gateway_address = ipaddress.ip_address(gateway)
        except ValueError:
            gateway_address = None
        if gateway_address is not None:
            for network in networks:
                if gateway_address in network:
                    return clamp_to_sweep(network)

    if not networks:
        return "192.168.1.0/24"
    best = min(networks, key=lambda network: network.num_addresses)
    return clamp_to_sweep(best)


def _is_sweepable(network: ipaddress.IPv4Network) -> bool:
    """
    True for a subnet worth sweeping.

    Loopback and 169.254 are rejected: they describe segments nobody routes to,
    and scanning one only wastes a sweep. Link-local autoconfiguration addresses
    look private to :mod:`ipaddress` but belong to that same dead space.

    Being outside RFC 1918 is no longer disqualifying. A VPN is very often a
    public-looking overlay -- carrier-grade NAT at 100.64/10, or an outright
    public block handed out point to point -- and refusing those meant that
    picking the VPN adapter in the selector still swept the LAN behind it.
    The range reaching the scanner is the one the operator chose, so the
    address block is not what decides whether it is worth sweeping.
    """
    if network.is_loopback or network.is_link_local:
        return False
    if network.num_addresses <= 1:
        return False
    # A /0 or a /1 is not a network, it is the internet; sweeping it would be a
    # mistake rather than a scan.
    return network.prefixlen >= 8


def clamp_to_sweep(network: ipaddress.IPv4Network,
                   limit: int = 65534) -> str:
    """
    The network to actually offer, shrunk until it fits in ``limit`` addresses.

    A VPN frequently advertises a mask wide enough to cover the whole address
    space (this machine has one advertising /8, sixteen million hosts). Offering
    that as the suggested range is useless: the planner would refuse it and the
    operator would have to work out a sensible prefix themselves. Narrowing
    from the top keeps the adapter's own address inside the range, which is
    what makes the suggestion usable rather than arbitrary.
    """
    if network.num_addresses <= limit:
        return str(network)
    prefix = network.prefixlen
    while prefix < 32:
        prefix += 1
        candidate = ipaddress.ip_network(f"{network.network_address}/{prefix}")
        if candidate.num_addresses <= limit:
            break
    return str(candidate)


# ---------------------------------------------------------------------------
# Target expansion
# ---------------------------------------------------------------------------

#: Hard ceiling on the addresses one scan may expand to. A typo such as
#: ``10.0.0.0/8`` is sixteen million hosts; this is the difference between an
#: instant refusal and a machine that stops responding.
MAX_TARGETS = 65534

#: A span wider than this is refused rather than truncated silently, because
#: a truncated sweep reports "done" while quietly skipping addresses.
MAX_SPAN = 65534


@dataclass(frozen=True)
class TargetRange:
    """
    One parsed chunk of the target field.

    ``excluded`` counts the addresses the maths removed: the network and
    broadcast addresses of a CIDR block. A free span has none, because its
    endpoints were typed on purpose and are swept as given.
    """

    text: str
    kind: str                 # "cidr" | "span" | "single"
    first: str
    last: str
    count: int
    excluded: int = 0

    def addresses(self) -> range:
        """Inclusive integer span, ready to be capped by the caller."""
        return range(int(ipaddress.ip_address(self.first)),
                     int(ipaddress.ip_address(self.last)) + 1)


@dataclass(frozen=True)
class TargetPlan:
    """
    What a typed range really means, worked out before any thread starts.

    The UI shows this the moment the field changes, so the operator knows how
    many addresses are about to be evaluated instead of finding out from a
    progress bar halfway through.
    """

    ranges: tuple[TargetRange, ...] = ()
    total: int = 0
    first: str = ""
    last: str = ""
    #: Chunks that could not be parsed, kept verbatim so the UI can say which.
    problems: tuple[str, ...] = ()
    #: True when the input asked for more than :data:`MAX_TARGETS`.
    truncated: bool = False

    @property
    def is_empty(self) -> bool:
        return self.total == 0

    @property
    def excluded(self) -> int:
        """Network and broadcast addresses dropped across every block."""
        return sum(item.excluded for item in self.ranges)

    def addresses(self, limit: int = MAX_TARGETS) -> list[str]:
        """
        Expand to address strings, deduplicated and hard-capped.

        Iterates lazily on purpose: materialising ``10.0.0.0/8`` first and
        trimming afterwards is what made a mistyped block exhaust memory.
        """
        out: list[str] = []
        seen: set[int] = set()
        for item in self.ranges:
            for value in item.addresses():
                if len(out) >= limit:
                    return out
                if value in seen:
                    continue
                seen.add(value)
                out.append(str(ipaddress.ip_address(value)))
        return out


def _parse_cidr(text: str) -> TargetRange:
    """A CIDR block, minus its network and broadcast addresses."""
    network = ipaddress.ip_network(text, strict=False)
    size = network.num_addresses
    base = int(network.network_address)

    # RFC 3021: in a /31 both addresses are endpoints, and a /32 is one host.
    # Only a wider block owns a network and a broadcast address.
    if isinstance(network, ipaddress.IPv4Network) and network.prefixlen <= 30:
        first, last, excluded = base + 1, base + size - 2, 2
    else:
        first, last, excluded = base, base + size - 1, 0

    return TargetRange(
        text=text, kind="cidr",
        first=str(ipaddress.ip_address(first)),
        last=str(ipaddress.ip_address(last)),
        count=max(0, last - first + 1), excluded=excluded,
    )


def _parse_span(text: str) -> TargetRange:
    """A free ``from-to`` span, taken exactly as typed."""
    start_text, _, end_text = text.partition("-")
    start = int(ipaddress.ip_address(start_text.strip()))
    end = int(ipaddress.ip_address(end_text.strip()))
    low, high = sorted((start, end))
    if high - low + 1 > MAX_SPAN:
        raise ValueError("span too wide")
    return TargetRange(
        text=text, kind="span",
        first=str(ipaddress.ip_address(low)),
        last=str(ipaddress.ip_address(high)),
        count=high - low + 1,
    )


def plan_targets(target_range: str, limit: int = MAX_TARGETS) -> TargetPlan:
    """
    Work out the addresses a target field asks for, without expanding them.

    Accepts CIDR blocks (``192.168.1.0/24``), free spans
    (``192.168.1.10-192.168.1.60``), single addresses and any comma, semicolon
    or space separated mix of the three. Unparsable chunks are reported
    instead of dropped, and a block wider than ``limit`` is flagged rather
    than silently trimmed.
    """
    ranges: list[TargetRange] = []
    problems: list[str] = []
    truncated = False

    for chunk in target_range.replace(";", ",").replace(" ", ",").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            if "/" in chunk:
                ranges.append(_parse_cidr(chunk))
            elif "-" in chunk:
                ranges.append(_parse_span(chunk))
            else:
                address = ipaddress.ip_address(chunk)
                ranges.append(TargetRange(
                    text=chunk, kind="single", first=str(address),
                    last=str(address), count=1,
                ))
        except ValueError:
            problems.append(chunk)

    total = sum(item.count for item in ranges)
    if total > limit:
        truncated = True

    first = last = ""
    if ranges:
        ordered = sorted(ranges,
                         key=lambda item: int(ipaddress.ip_address(item.first)))
        first = ordered[0].first
        last = max((item.last for item in ranges),
                   key=lambda value: int(ipaddress.ip_address(value)))

    return TargetPlan(tuple(ranges), total, first, last, tuple(problems), truncated)


# ---------------------------------------------------------------------------
# VPN posture
# ---------------------------------------------------------------------------

def get_virtual_adapters() -> list[str]:
    """Names of active virtual or VPN interfaces on this machine."""
    import psutil

    virtual: list[str] = []
    for raw_name, interface in psutil.net_if_addrs().items():
        name = (
            raw_name.decode("utf-8", "ignore")
            if isinstance(raw_name, bytes)
            else str(raw_name)
        )
        has_ipv4 = any(addr.family == socket.AF_INET for addr in interface)
        if has_ipv4 and is_virtual_adapter(name):
            virtual.append(name)
    return virtual


def get_running_vpn_processes() -> list[str]:
    """Names of VPN or proxy client processes currently executing."""
    import psutil

    found: set[str] = set()
    try:
        for process in psutil.process_iter(["name"]):
            raw_name = process.info.get("name") or ""
            lowered = raw_name.lower().removesuffix(".exe")
            if any(noise in lowered for noise in VPN_PROCESS_NOISE):
                continue
            if any(hint in lowered for hint in VPN_PROCESS_HINTS):
                found.add(raw_name)
    except (psutil.Error, OSError):
        pass
    return sorted(found)


def get_local_proxy_ports(timeout: float = 0.3) -> dict[int, str]:
    """Proxy or tunnel ports currently listening on the loopback address."""
    open_ports: dict[int, str] = {}
    for port, label in LOCAL_PROXY_PORTS.items():
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(timeout)
        try:
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                open_ports[port] = label
        except OSError:
            continue
        finally:
            probe.close()
    return open_ports


def vpn_report() -> dict[str, object]:
    """Aggregated VPN and proxy posture of the local machine."""
    adapters = get_virtual_adapters()
    processes = get_running_vpn_processes()
    proxies = get_local_proxy_ports()

    reasons = [
        f"virtual adapters: {', '.join(adapters)}" if adapters else "",
        f"processes: {', '.join(processes)}" if processes else "",
        f"local proxies: {', '.join(map(str, proxies))}" if proxies else "",
    ]
    return {
        "is_vpn_active": bool(adapters or processes),
        "virtual_adapters": adapters,
        "vpn_processes": processes,
        "local_proxy_ports": proxies,
        "summary": "; ".join(filter(None, reasons)) or "No VPN detected",
    }
