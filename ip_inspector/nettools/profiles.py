"""Selectable scan profiles.

A profile bundles the whole tuning of a scan: which ports to probe, how
patient to be, how many sockets to keep open, and whether to spend extra
time on banner grabbing or device identification. Switching mode is then
a single click instead of hand-editing the port list and hoping the time
outs suit the question being asked.

The three shipped profiles answer different operational questions:

* **quick**  - "what is alive right now?"
* **deep**   - "give me the full attack surface of these hosts"
* **iot**    - "where are the cameras, NVRs and smart devices?"
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.models import COMMON_PORTS

#: Ports that answer the question "is this host reachable at all".
CRITICAL_PORTS: tuple[int, ...] = (80, 443, 3389, 22)

#: Full low range; anything above 1024 is rarely reachable from a LAN.
DEEP_PORTS: tuple[int, ...] = tuple(range(1, 1025))

#: Video, streaming and embedded-web ports used by cameras and NVRs.
IOT_PORTS: tuple[int, ...] = (
    80,      # embedded web interface
    81,      # alternate web interface
    443,     # web over TLS
    554,     # RTSP, the main camera stream protocol
    8554,    # RTSP over TLS
    37777,   # Dahua / ONVIF-ish management
    34567,   # TP-Link / some NVR web
    37215,   # Huawei
    5000,    # UPnP / Flask admin panels
    8000,    # UPnP alt
    8080,    # generic proxy / admin
    9530,    # Realtek SDK backdoor surface
    8899,    # some NVR web interfaces
)


@dataclass(frozen=True)
class ScanProfile:
    """A named bundle of scan settings."""

    key: str
    ports: tuple[int, ...]
    port_timeout: float = 1.0
    concurrency: int = 500
    resolve_hostnames: bool = True
    identify_models: bool = True
    advanced_banners: bool = False
    icon: str = ""
    #: Device classes the classifier should expect in this mode.
    hints: tuple[str, ...] = field(default=())

    @property
    def port_count(self) -> int:
        return len(self.ports)

    def apply(self, request):
        """Copy this profile's settings onto a :class:`ScanRequest`."""
        request.ports = tuple(self.ports)
        request.port_timeout = self.port_timeout
        request.concurrency = self.concurrency
        request.resolve_hostnames = self.resolve_hostnames
        request.identify_models = self.identify_models
        request.advanced_banners = self.advanced_banners
        request.profile = self.key
        request.device_hints = self.hints
        return request

    def ports_label(self, limit: int = 60) -> str:
        """Compact description of the port set for the UI."""
        ports = self.ports
        if len(ports) > limit:
            return f"1-1024 ({len(ports)})"
        if len(ports) <= 8:
            return ", ".join(str(p) for p in ports)
        return f"{', '.join(str(p) for p in ports[:limit])}... ({len(ports)})"


QUICK = ScanProfile(
    key="quick",
    ports=CRITICAL_PORTS,
    port_timeout=0.6,
    concurrency=800,
    resolve_hostnames=True,
    identify_models=True,
    advanced_banners=False,
    hints=("online",),
)

DEEP = ScanProfile(
    key="deep",
    ports=DEEP_PORTS,
    port_timeout=1.2,
    concurrency=250,
    resolve_hostnames=True,
    identify_models=True,
    advanced_banners=True,
    hints=("exposure",),
)

IOT = ScanProfile(
    key="iot",
    ports=IOT_PORTS,
    port_timeout=1.0,
    concurrency=400,
    resolve_hostnames=True,
    identify_models=True,
    advanced_banners=False,
    hints=("IP Camera", "IoT Device", "Printer"),
)

#: Selection order is the order shown in the UI.
PROFILES: tuple[ScanProfile, ...] = (QUICK, DEEP, IOT)

#: Fallback when the user edited the port list by hand.
CUSTOM = ScanProfile(
    key="custom",
    ports=COMMON_PORTS,
    port_timeout=1.0,
    concurrency=500,
    hints=(),
)


def get_profile(key: str) -> ScanProfile:
    """Look a profile up by key, falling back to the custom one."""
    for profile in PROFILES:
        if profile.key == key:
            return profile
    return CUSTOM