"""
Passive-style service discovery: SSDP/UPnP and mDNS (Bonjour).

Port scans and pings say *that* a device exists. These two protocols are how
devices describe *what* they are, in their own words:

* **SSDP/UPnP** - TVs, media players, routers, printers, NAS boxes and
  consoles answer an ``M-SEARCH`` with a URL to an XML description that
  carries a friendly name, the manufacturer and the exact model.
* **mDNS/DNS-SD** - phones, Chromecasts, Apple devices, printers and smart
  home gear publish service records such as ``_googlecast._tcp`` or
  ``_ipp._tcp``, often with TXT data like ``fn=Living Room TV`` or
  ``ty=HP LaserJet Pro``.

Both are one multicast question on the local segment; answers come back for
about two seconds. :class:`LanDiscovery` runs them on a background thread
while the sweep is busy, so they add no time to a scan.

Everything here is best effort and never raises.
"""

from __future__ import annotations

import random
import re
import socket
import struct
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from xml.etree import ElementTree

from .hostnames import _encode_name, _read_name, _skip_name


def _local_addresses() -> list[str]:
    """IPv4 addresses of the usable local adapters (multicast goes out each)."""
    from .utils import iter_local_ipv4

    try:
        return [ip for ip, _mask in iter_local_ipv4()
                if not ip.startswith(("127.", "169.254."))]
    except Exception:  # noqa: BLE001
        return []


def _send_on_every_interface(sock: socket.socket, payloads: list[bytes],
                             group: tuple[str, int]) -> None:
    """Windows sends multicast out of one adapter only unless told otherwise."""
    interfaces = _local_addresses() or [""]
    for address in interfaces:
        try:
            if address:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                                socket.inet_aton(address))
            for payload in payloads:
                sock.sendto(payload, group)
        except OSError:
            continue

SSDP_ADDRESS = ("239.255.255.250", 1900)
MDNS_ADDRESS = ("224.0.0.251", 5353)
#: How long each protocol listens for answers.
LISTEN_SECONDS = 2.5
#: Per-device budget to download a UPnP description.
DESCRIPTION_TIMEOUT = 1.5

#: DNS-SD service types worth asking for, and what each one says about the
#: device that publishes it.
MDNS_SERVICES: dict[str, str] = {
    "_googlecast._tcp.local": "Chromecast / Google Cast",
    "_airplay._tcp.local": "AirPlay",
    "_raop._tcp.local": "AirPlay audio",
    "_companion-link._tcp.local": "Apple device",
    "_apple-mobdev2._tcp.local": "Apple mobile device",
    "_device-info._tcp.local": "Device info",
    "_ipp._tcp.local": "IPP printing",
    "_ipps._tcp.local": "IPP printing (TLS)",
    "_printer._tcp.local": "LPD printing",
    "_pdl-datastream._tcp.local": "Raw printing",
    "_scanner._tcp.local": "Network scanner",
    "_uscan._tcp.local": "eSCL scanning",
    "_hap._tcp.local": "HomeKit accessory",
    "_matter._tcp.local": "Matter",
    "_spotify-connect._tcp.local": "Spotify Connect",
    "_sonos._tcp.local": "Sonos",
    "_amzn-wplay._tcp.local": "Amazon Fire / Echo",
    "_androidtvremote2._tcp.local": "Android TV",
    "_smb._tcp.local": "File sharing (SMB)",
    "_afpovertcp._tcp.local": "File sharing (AFP)",
    "_ssh._tcp.local": "SSH",
    "_http._tcp.local": "Web interface",
    "_workstation._tcp.local": "Workstation",
    "_rdlink._tcp.local": "Apple device",
}

_TYPE_PTR, _TYPE_TXT, _TYPE_SRV, _TYPE_A = 12, 16, 33, 1


@dataclass
class DeviceInfo:
    """What a device said about itself over SSDP/UPnP and mDNS."""

    ip: str
    friendly_name: str = ""
    manufacturer: str = ""
    model: str = ""
    model_number: str = ""
    upnp_types: set[str] = field(default_factory=set)
    #: DNS-SD service types published (e.g. "_googlecast._tcp").
    services: set[str] = field(default_factory=set)
    #: Instance names published over mDNS ("Living Room TV._googlecast...").
    instance_names: set[str] = field(default_factory=set)
    txt: dict[str, str] = field(default_factory=dict)
    server: str = ""
    mdns_host: str = ""

    def merge(self, other: "DeviceInfo") -> None:
        for name in ("friendly_name", "manufacturer", "model", "model_number",
                     "server", "mdns_host"):
            if not getattr(self, name) and getattr(other, name):
                setattr(self, name, getattr(other, name))
        self.upnp_types |= other.upnp_types
        self.services |= other.services
        self.instance_names |= other.instance_names
        for key, value in other.txt.items():
            self.txt.setdefault(key, value)

    @property
    def best_name(self) -> str:
        """The name a person gave the device, if it published one."""
        for candidate in (self.txt.get("fn"), self.friendly_name, self.txt.get("n"),
                          *sorted(self.instance_names)):
            if candidate and not _looks_generated(candidate):
                return candidate.strip()
        return ""

    @property
    def best_model(self) -> str:
        """Manufacturer's model string, from whichever protocol had one."""
        for candidate in (self.txt.get("md"), self.txt.get("ty"), self.txt.get("product", "")
                          .strip("()"), self.txt.get("model"), self.model):
            if candidate:
                model = candidate.strip()
                if self.model_number and self.model_number not in model:
                    model = f"{model} {self.model_number}"
                return model
        return ""


#: Friendly names that only restate the UPnP device class.
_GENERIC_NAMES = re.compile(
    r"\b(igd|internet ?gateway ?device|wan(connection)?device|upnp|dlna|"
    r"media ?(server|renderer)|basic ?device|root ?device)\b", re.IGNORECASE)


def _looks_generated(name: str) -> bool:
    """Names that are just a MAC, a UUID or the UPnP device class."""
    if _GENERIC_NAMES.search(name):
        return True
    compact = re.sub(r"[^0-9a-f]", "", name.lower())
    return len(compact) >= 12 and len(compact) >= len(name) * 0.7


# --------------------------------------------------------------------------- #
# SSDP / UPnP
# --------------------------------------------------------------------------- #
def ssdp_search(seconds: float = LISTEN_SECONDS) -> dict[str, dict[str, str]]:
    """Send one M-SEARCH and collect ``{ip: {"location", "server", "st"}}``."""
    message = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDRESS[0]}:{SSDP_ADDRESS[1]}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode("ascii")
    found: dict[str, dict[str, str]] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(0.3)
            # UDP: a second copy is cheap insurance against a dropped packet.
            _send_on_every_interface(sock, [message, message], SSDP_ADDRESS)
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                try:
                    data, (ip, _port) = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                headers = _http_headers(data.decode("utf-8", "replace"))
                entry = found.setdefault(ip, {})
                for key in ("location", "server", "st"):
                    if headers.get(key) and not entry.get(key):
                        entry[key] = headers[key]
    except OSError:
        return found
    return found


def _http_headers(text: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in text.split("\r\n")[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers[key.strip().lower()] = value.strip()
    return headers


def fetch_upnp_description(location: str, timeout: float = DESCRIPTION_TIMEOUT) -> DeviceInfo:
    """Download and parse a UPnP device description (rootDesc.xml)."""
    host = re.sub(r"^https?://([^/:]+).*$", r"\1", location)
    info = DeviceInfo(ip=host)
    if not location.lower().startswith("http://"):
        return info
    try:
        request = urllib.request.Request(location, headers={"User-Agent": "IP-Scanner/2"})
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            body = response.read(65536)
    except Exception:  # noqa: BLE001 - a description is a nicety
        return info
    return parse_upnp_description(body, host)


def parse_upnp_description(body: bytes, ip: str) -> DeviceInfo:
    info = DeviceInfo(ip=ip)
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return info

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    devices = [element for element in root.iter() if local(element.tag) == "device"]
    for index, device in enumerate(devices):
        values = {local(child.tag): (child.text or "").strip() for child in device}
        if values.get("deviceType"):
            info.upnp_types.add(values["deviceType"])
        if index == 0:                       # the root device describes the box
            info.friendly_name = values.get("friendlyName", "")
            info.manufacturer = values.get("manufacturer", "")
            info.model = values.get("modelName", "") or values.get("modelDescription", "")
            info.model_number = values.get("modelNumber", "")
    if info.model_number and info.model_number.lower() in info.model.lower():
        info.model_number = ""
    return info


# --------------------------------------------------------------------------- #
# mDNS / DNS-SD
# --------------------------------------------------------------------------- #
def _mdns_query(names: list[str], qtype: int = _TYPE_PTR) -> bytes:
    """One packet asking several questions, with the unicast-response bit."""
    header = struct.pack("!HHHHHH", 0, 0, len(names), 0, 0, 0)
    body = b"".join(_encode_name(name) + struct.pack("!HH", qtype, 0x8001) for name in names)
    return header + body


def parse_mdns_response(data: bytes, ip: str) -> DeviceInfo:
    """Collect services, instance names, TXT data and the host name."""
    info = DeviceInfo(ip=ip)
    try:
        _ident, _flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
        offset = 12
        for _ in range(qd):
            offset = _skip_name(data, offset) + 4
        for _ in range(an + ns + ar):
            name, offset = _read_name(data, offset)
            rtype, _rclass, _ttl, length = struct.unpack("!HHIH", data[offset:offset + 10])
            offset += 10
            rdata_start, rdata_end = offset, offset + length
            if rtype == _TYPE_PTR:
                target, _ = _read_name(data, rdata_start)
                if name.endswith(("._tcp.local", "._udp.local")) and not name.startswith("_services"):
                    service = name.removesuffix(".local")
                    info.services.add(service)
                    instance = target.split("._", 1)[0]
                    if instance:
                        info.instance_names.add(instance.replace("\\032", " "))
            elif rtype == _TYPE_TXT:
                position = rdata_start
                while position < rdata_end:
                    size = data[position]
                    entry = data[position + 1:position + 1 + size].decode("utf-8", "replace")
                    key, sep, value = entry.partition("=")
                    if sep and key and value:
                        info.txt.setdefault(key.lower(), value)
                    position += 1 + size
            elif rtype == _TYPE_SRV:
                host, _ = _read_name(data, rdata_start + 6)
                if host and not info.mdns_host:
                    info.mdns_host = host.removesuffix(".local").rstrip(".")
            elif rtype == _TYPE_A and name.endswith(".local") and not info.mdns_host:
                info.mdns_host = name.removesuffix(".local")
            offset = rdata_end
    except (struct.error, IndexError, ValueError):
        pass
    return info


def mdns_browse(seconds: float = LISTEN_SECONDS) -> dict[str, DeviceInfo]:
    """Ask the segment for every service type in :data:`MDNS_SERVICES`."""
    found: dict[str, DeviceInfo] = {}
    services = list(MDNS_SERVICES)
    own = set(_local_addresses())
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Listening on 5353 as a member of the group also catches devices
            # that ignore the unicast-response bit and answer to the group.
            try:
                sock.bind(("", MDNS_ADDRESS[1]))
                for address in own:
                    try:
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                        socket.inet_aton(MDNS_ADDRESS[0]) + socket.inet_aton(address))
                    except OSError:
                        pass
            except OSError:
                sock.bind(("", 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            sock.settimeout(0.3)
            # Several small packets rather than one big one: some responders
            # ignore queries carrying more than a handful of questions.
            _send_on_every_interface(
                sock, [_mdns_query(services[start:start + 6])
                       for start in range(0, len(services), 6)], MDNS_ADDRESS)
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                try:
                    data, (ip, _port) = sock.recvfrom(9000)
                except socket.timeout:
                    continue
                if ip.startswith("127.") or ip in own:
                    continue
                parsed = parse_mdns_response(data, ip)
                if not (parsed.services or parsed.txt or parsed.mdns_host):
                    continue
                if ip in found:
                    found[ip].merge(parsed)
                else:
                    found[ip] = parsed
    except OSError:
        return found
    return found


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
class LanDiscovery:
    """Run SSDP and mDNS discovery in the background during a scan."""

    def __init__(self, seconds: float = LISTEN_SECONDS) -> None:
        self._seconds = seconds
        self._results: dict[str, DeviceInfo] = {}
        self._thread = threading.Thread(target=self._run, name="lan-discovery", daemon=True)

    def start(self) -> "LanDiscovery":
        self._thread.start()
        return self

    def _run(self) -> None:
        with ThreadPoolExecutor(max_workers=2) as pool:
            ssdp_future = pool.submit(ssdp_search, self._seconds)
            mdns_future = pool.submit(mdns_browse, self._seconds)
            ssdp = ssdp_future.result()
            mdns = mdns_future.result()
        results: dict[str, DeviceInfo] = dict(mdns)
        locations = {ip: entry["location"] for ip, entry in ssdp.items() if entry.get("location")}
        with ThreadPoolExecutor(max_workers=16) as pool:
            described = dict(zip(locations, pool.map(fetch_upnp_description, locations.values())))
        for ip, entry in ssdp.items():
            info = described.get(ip) or DeviceInfo(ip=ip)
            info.ip = ip
            info.server = entry.get("server", "")
            if ip in results:
                results[ip].merge(info)
            else:
                results[ip] = info
        self._results = results

    def results(self, timeout: float = 6.0) -> dict[str, DeviceInfo]:
        """Wait (bounded) for discovery to finish and return what it found."""
        self._thread.join(timeout)
        return dict(self._results)


__all__ = ["DeviceInfo", "LanDiscovery", "MDNS_SERVICES", "fetch_upnp_description",
           "mdns_browse", "parse_mdns_response", "parse_upnp_description", "ssdp_search"]


def _self_test() -> None:  # pragma: no cover - manual helper
    for ip, info in sorted(LanDiscovery().start().results().items()):
        print(ip, info.best_name, "|", info.manufacturer, "|", info.best_model, "|",
              sorted(info.services), sorted(info.upnp_types))


if __name__ == "__main__":  # pragma: no cover
    random.seed()
    _self_test()
