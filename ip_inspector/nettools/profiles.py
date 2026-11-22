"""Selectable scan profiles.

A profile bundles the whole tuning of a scan: which ports to probe, how
patient to be, how many sockets to keep open, and whether to spend extra
time on name resolution or device identification. Switching mode is then a
single click instead of hand-editing the port list.

Each profile answers a different operational question:

* **quick**     - "what is alive right now, and is anything obvious open?"
* **standard**  - "the services a LAN usually exposes" (top ~100 ports)
* **full**      - "the whole well-known range" (1-1024)
* **iot**       - "where are the cameras, NVRs and smart devices?"
* **discovery** - "which addresses answer?" (no port scan at all)
* **custom**    - the operator's own port list
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field

from ..core.models import ScanRequest

#: A handful of ports that identify most hosts on a LAN.
QUICK_PORTS: tuple[int, ...] = (21, 22, 23, 53, 80, 135, 139, 443, 445, 3389, 8080)

#: The ports most often found open on home and office networks.
STANDARD_PORTS: tuple[int, ...] = tuple(sorted({
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
    49152, 49153, 49154, 49155, 49156, 49157,
}))

#: Full well-known range.
FULL_PORTS: tuple[int, ...] = tuple(range(1, 1025))

#: Video, streaming and embedded-web ports used by cameras and NVRs.
IOT_PORTS: tuple[int, ...] = (
    80, 81, 443, 554, 1883, 5000, 8000, 8080, 8443, 8554, 8883, 8899,
    9530, 34567, 37215, 37777,
)


@dataclass(frozen=True)
class ScanProfile:
    """A named bundle of scan settings."""

    key: str
    name: str
    description: str
    ports: tuple[int, ...]
    port_timeout: float = 0.5
    concurrency: int = 1000
    scan_ports: bool = True
    resolve_hostnames: bool = True
    identify_models: bool = True
    #: Device classes the identification phase should look harder for.
    hints: tuple[str, ...] = field(default=())

    @property
    def port_count(self) -> int:
        return len(self.ports) if self.scan_ports else 0

    def to_request(self, target_range: str, **overrides) -> ScanRequest:
        """Build a :class:`ScanRequest`; ``overrides`` win over the profile."""
        request = ScanRequest(
            target_range=target_range,
            ports=tuple(self.ports),
            scan_ports_enabled=self.scan_ports,
            resolve_hostnames=self.resolve_hostnames,
            identify_models=self.identify_models,
            profile=self.key,
            device_hints=self.hints,
            port_timeout=self.port_timeout,
            concurrency=self.concurrency,
        )
        return dataclasses.replace(request, **overrides) if overrides else request

    def ports_label(self) -> str:
        """Compact description of the port set for the UI."""
        if not self.scan_ports:
            return "no port scan"
        if self.ports == FULL_PORTS:
            return "ports 1-1024"
        if len(self.ports) <= 8:
            return "ports " + ", ".join(str(p) for p in self.ports)
        return f"{len(self.ports)} ports"


QUICK = ScanProfile(
    "quick", "Quick", "Live hosts and the most revealing ports.",
    QUICK_PORTS, port_timeout=0.4, concurrency=1000,
)
STANDARD = ScanProfile(
    "standard", "Standard", "The ~100 services LANs usually expose.",
    STANDARD_PORTS, port_timeout=0.5, concurrency=1500,
)
FULL = ScanProfile(
    "full", "Full (1-1024)", "Every well-known port. Slowest, most complete.",
    FULL_PORTS, port_timeout=0.5, concurrency=2000,
)
IOT = ScanProfile(
    "iot", "IoT / Cameras", "Cameras, NVRs, MQTT brokers and smart devices.",
    IOT_PORTS, port_timeout=0.8, concurrency=800,
    hints=("IP Camera", "IoT Device", "Printer"),
)
DISCOVERY = ScanProfile(
    "discovery", "Ping sweep only", "Find live hosts; skip the port scan.",
    (), scan_ports=False, identify_models=False,
)
CUSTOM = ScanProfile(
    "custom", "Custom ports", "Probe exactly the ports you type.",
    STANDARD_PORTS,
)

#: Selection order is the order shown in the UI.
PROFILES: tuple[ScanProfile, ...] = (QUICK, STANDARD, FULL, IOT, DISCOVERY, CUSTOM)


def get_profile(key: str) -> ScanProfile:
    """Look a profile up by key or display name, falling back to Standard."""
    for profile in PROFILES:
        if key in (profile.key, profile.name):
            return profile
    return STANDARD


def parse_ports(text: str, limit: int = 65535) -> tuple[int, ...]:
    """
    Parse a port list such as ``"22, 80, 443, 8000-8100"``.

    Raises :class:`ValueError` with a readable message on bad input, so the
    UI can show it as-is.
    """
    ports: set[int] = set()
    for chunk in text.replace(";", ",").replace(" ", ",").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            low_text, _, high_text = chunk.partition("-")
            try:
                low, high = int(low_text), int(high_text)
            except ValueError:
                raise ValueError(f"'{chunk}' is not a port range") from None
            if low > high:
                low, high = high, low
        else:
            try:
                low = high = int(chunk)
            except ValueError:
                raise ValueError(f"'{chunk}' is not a port number") from None
        if low < 1 or high > 65535:
            raise ValueError(f"'{chunk}' is outside 1-65535")
        ports.update(range(low, high + 1))
        if len(ports) > limit:
            raise ValueError(f"Too many ports (more than {limit})")
    if not ports:
        raise ValueError("Type at least one port, e.g. 22, 80, 443, 8000-8100")
    return tuple(sorted(ports))
