"""Domain models shared by the scanner core and the user interface layer.

This module is intentionally dependency-free: it must stay importable on
its own so the UI can be reasoned about (and type-checked) without
touching sockets, scapy or tkinter.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

PortState = Literal["open", "closed", "filtered"]

#: Ports most often exposed by reachable machines. Kept as the fallback name
#: for the well-known services and the report writer.
COMMON_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 587, 631,
    993, 995, 1433, 3306, 3389, 5000, 5432, 5900, 6379, 8080, 8443, 9100,
)

#: Every port the scanner sweeps. The operator no longer picks a port list, so
#: the range is fixed and every sweep asks the same question: which of these is
#: reachable. Anything above 1024 is rarely reachable from a LAN and is left
#: to the Tools tab's own diagnostics.
SCAN_PORTS: tuple[int, ...] = tuple(range(1, 1025))

#: Fallback service name when a port is open but stays silent on connect.
KNOWN_SERVICES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 587: "SMTP", 631: "IPP", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5000: "UPnP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 9100: "Raw-Print",
}


def normalize_mac_address(mac_address: str | None) -> str | None:
    """Normalise any MAC notation to the canonical AA:BB:CC:DD:EE:FF form."""
    if not mac_address:
        return None
    hex_digits = "".join(char for char in mac_address if char.isalnum())
    if len(hex_digits) != 12:
        return None
    octets = [hex_digits[i : i + 2] for i in range(0, 12, 2)]
    return ":".join(octets).upper()


def oui_prefix(mac_address: str | None) -> str | None:
    """Return the 3-byte OUI prefix used for vendor lookups."""
    normalized = normalize_mac_address(mac_address)
    return normalized[:8] if normalized else None


@dataclass(slots=True)
class Port:
    """Result of probing a single TCP port."""

    number: int
    state: PortState
    service: str = ""
    banner: str = ""
    #: Release parsed out of the banner, e.g. "8.9p1". Kept apart from the
    #: banner so the table can show the number without the rest.
    version: str = ""
    latency_ms: float | None = None

    @property
    def is_open(self) -> bool:
        return self.state == "open"

    @property
    def label(self) -> str:
        """Compact label for the GUI 'Ports' column."""
        if not self.is_open:
            return ""
        name = f"{self.number}/{self.service}" if self.service else str(self.number)
        return f"{name} {self.version}" if self.version else name


@dataclass(slots=True)
class Device:
    """A host discovered on the network, enriched as the scan progresses."""

    ip_address: str
    mac_address: str | None = None
    hostname: str = ""
    vendor: str = ""
    model: str = ""
    device_type: str = "Unknown"
    is_vpn_active: bool = False
    open_ports: list[Port] = field(default_factory=list)

    # Secondary evidence used for classification and reporting.
    is_alive: bool = True
    risk_score: int = 0
    #: Inventory verdict: new, known, returning or blank.
    inventory_state: str = ""
    first_seen: str = ""
    ttl: int | None = None
    #: TCP window advertised in the SYN-ACK, when raw sockets allowed a look.
    tcp_window: int | None = None
    #: Operating system deduced from the TTL and the TCP window, when the
    #: evidence was strong enough to say something.
    os_name: str = ""
    response_time_ms: float | None = None
    discovery_method: str = ""

    def __post_init__(self) -> None:
        self.mac_address = normalize_mac_address(self.mac_address)

    #: Offline heuristic findings, filled by the exposure engine so the
    #: table and the report can show what is wrong without re-probing.
    findings: list[SecurityFinding] = field(default_factory=list)

    @property
    def vendor_label(self) -> str:
        """Vendor, falling back to the model when the OUI is unknown."""
        return self.vendor or self.model or "-"

    @property
    def model_label(self) -> str:
        """Detected model, falling back to the OS guess, then an em dash."""
        return self.model or self.os_name or "-"

    @property
    def latency_label(self) -> str:
        """Round-trip time in milliseconds, as shown in the table."""
        return f"{self.response_time_ms:.0f}" if self.response_time_ms else "-"

    @property
    def is_new_device(self) -> bool:
        """True when the inventory flagged this device as never seen before."""
        return self.inventory_state == "new"

    @property
    def ttl_label(self) -> str:
        """Observed IP TTL, which hints at the operating system."""
        return str(self.ttl) if self.ttl else "-"

    @property
    def ports_summary(self) -> str:
        """Comma separated list of the open ports, ordered numerically."""
        open_ports = sorted((p for p in self.open_ports if p.is_open),
                            key=lambda port: port.number)
        return ", ".join(port.label for port in open_ports)

    def has_port(self, number: int) -> bool:
        return any(port.number == number and port.is_open for port in self.open_ports)

    def to_row(self) -> list[str]:
        """Flat representation matching the GUI column order."""
        return [
            self.ip_address,
            "Online" if self.is_alive else "Offline",
            self.hostname or "-",
            self.mac_address or "-",
            self.vendor_label,
            self.model_label,
            self.os_name or "-",
            self.device_type,
            "Yes" if self.is_vpn_active else "-",
            self.ttl_label,
            self.latency_label,
            self.discovery_method or "-",
            self.ports_summary,
        ]


    @property
    def status_text(self) -> str:
        """Short connectivity label shown in the Status column."""
        return "Online" if self.is_alive else "Offline"

    @property
    def open_port_count(self) -> int:
        """Number of ports currently in the open state."""
        return sum(1 for port in self.open_ports if port.is_open)

    @property
    def alerts_count(self) -> int:
        """How many heuristic findings need attention on this host."""
        return sum(1 for finding in self.findings
                   if finding.severity in ("critical", "high"))

    @property
    def worst_severity(self) -> str:
        """Most serious finding for this host, or an empty string."""
        return self.findings[0].severity if self.findings else ""

    def sort_key(self, column: str) -> object:
        """
        Return a comparable key for a named column.

        Used by the table sorter so ordering is type-aware: numeric fields
        sort numerically and absent values sink to the bottom.
        """
        if column == "ip":
            return tuple(int(octet) for octet in self.ip_address.split("."))
        if column == "hostname":
            return self.hostname.lower()
        if column == "vendor":
            return (self.vendor or self.model).lower()
        if column == "model":
            return self.model.lower()
        if column == "type":
            return self.device_type.lower()
        if column == "ttl":
            return -(self.ttl or 0)
        if column == "latency":
            return (self.response_time_ms or 9999)
        if column == "method":
            return self.discovery_method.lower()
        if column == "risk":
            return -self.risk_score
        if column == "alerts":
            return (-self.alerts_count, -self.risk_score)
        if column == "ports":
            return -self.open_port_count
        return ""


@dataclass(slots=True)
class ScanRequest:
    """Immutable description of a single scan run."""

    target_range: str
    ports: tuple[int, ...] = SCAN_PORTS
    resolve_hostnames: bool = True
    #: Ports are always swept. The switch that used to disable this is gone:
    #: a sweep that silently skipped them was not what "scan" meant to anyone.
    scan_ports_enabled: bool = True
    identify_models: bool = True
    #: Scan profile key that produced this request.
    profile: str = "full"
    #: Read deeper banners (UPnP, ONVIF, product strings).
    advanced_banners: bool = False
    #: Profile-specific device classes to look for.
    device_hints: tuple[str, ...] = ()
    port_timeout: float = 1.0
    concurrency: int = 500
    #: Local adapter to sweep on; empty means "let the OS decide".
    interface: str = ""


@dataclass(slots=True)
class ScannerEvent:
    """
    Progress record emitted by the worker thread and consumed by the UI.

    A single queue carries every update, which keeps the worker thread
    completely free of tkinter calls.
    """

    phase: str
    message: str = ""
    completed: int = 0
    total: int = 0
    device: Device | None = None
    is_error: bool = False
# ---------------------------------------------------------------------------
# Tooling and security audit models
# ---------------------------------------------------------------------------

#: Severity levels used by the security audit, ordered from benign to critical.
Severity = Literal["info", "low", "medium", "high", "critical"]


@dataclass(slots=True)
class TracerouteHop:
    """
    A single router on the path towards a destination.

    A hop that did not answer keeps ``address="*"`` and an empty ``rtts``,
    which is the normal outcome behind a firewall and not an error.
    """

    hop: int
    address: str
    hostname: str = ""
    rtts: tuple[float, ...] = ()

    @property
    def responded(self) -> bool:
        """True when the router answered the probe."""
        return bool(self.rtts)

    @property
    def rtt(self) -> float | None:
        """Mean round-trip time, or ``None`` when the hop timed out."""
        return sum(self.rtts) / len(self.rtts) if self.rtts else None


@dataclass(slots=True)
class LatencyStats:
    """
    Summary of a rolling window of ping samples.

    ``jitter`` is the mean absolute difference between consecutive round
    trips, the variation an operator feels as stutter. ``loss`` is the share
    of probes that never came back, in percent. Every field is ``None`` or
    zero while no packet has been answered yet.
    """

    last: float | None = None
    minimum: float | None = None
    average: float | None = None
    maximum: float | None = None
    jitter: float | None = None
    sent: int = 0
    lost: int = 0
    loss: float = 0.0

    @property
    def answered(self) -> bool:
        """True once at least one probe came back."""
        return self.last is not None


def latency_stats(samples: Sequence[float | None]) -> LatencyStats:
    """
    Summarise a window of round trips, where ``None`` marks a lost packet.

    Pure and dependency-free so the graph, the status line and the report can
    never disagree about the same samples.
    """
    values = [value for value in samples if value is not None]
    stats = LatencyStats(sent=len(samples), lost=len(samples) - len(values))
    if samples:
        stats.loss = round(stats.lost * 100 / len(samples), 1)
    if not values:
        return stats

    stats.last = values[-1]
    stats.minimum = min(values)
    stats.maximum = max(values)
    stats.average = round(sum(values) / len(values), 1)
    deltas = [abs(second - first) for first, second in zip(values, values[1:])]
    if deltas:
        stats.jitter = round(sum(deltas) / len(deltas), 1)
    return stats


@dataclass(slots=True)
class SubnetInfo:
    """
    Full arithmetic of one CIDR block.

    Produced by :mod:`ip_inspector.tools` so the calculator can paint a
    widget per field instead of parsing its own text output.
    """

    cidr: str
    version: int
    prefixlen: int
    netmask: str
    wildcard: str
    network: str
    broadcast: str
    first_host: str
    last_host: str
    total_addresses: int
    usable_hosts: int
    is_private: bool


@dataclass(slots=True)
class ToolResult:
    """
    Outcome of a single reconnaissance tool run.

    Tools never raise: they return this record with ``ok=False`` and an
    ``error`` message so the UI can render partial results uniformly.

    ``hops`` and ``data`` carry the structured view of the richer tools
    (traceroute and the subnet calculator). The plain text stays in
    ``lines``/``output`` for the console pane.
    """

    name: str
    ok: bool = True
    output: str = ""
    lines: list[str] = field(default_factory=list)
    error: str = ""
    elapsed_ms: float | None = None
    hops: list[TracerouteHop] = field(default_factory=list)
    data: object | None = None


@dataclass(slots=True)
class TlsReport:
    """Result of inspecting the TLS certificate presented by a host."""

    host: str
    port: int = 443
    supported: bool = False
    protocol: str = ""
    cipher: str = ""
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    days_remaining: int | None = None
    subject_alt_names: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    error: str = ""


@dataclass(slots=True)
class HttpReport:
    """Security-posture report for an HTTP(S) endpoint."""

    url: str
    status_code: int | None = None
    server: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    findings: list[tuple[str, str]] = field(default_factory=list)
    elapsed_ms: float | None = None
    error: str = ""


@dataclass(slots=True)
class SecurityFinding:
    """A single security observation about a discovered device."""

    severity: Severity
    title: str
    detail: str
    target: str = ""
    #: Catalogue key and parameters for ``title``/``detail``. Heuristic
    #: findings are generated without knowing the active language, so the
    #: wording is resolved by the UI at render time; ``title``/``detail``
    #: stay filled with the default text for the report and for any other
    #: consumer that does not localise.
    title_key: str = ""
    detail_key: str = ""
    params: dict[str, object] = field(default_factory=dict)

    @property
    def sort_weight(self) -> int:
        order = ("critical", "high", "medium", "low", "info")
        return order.index(self.severity) if self.severity in order else len(order)


#: Human-readable labels for each severity level.
SEVERITY_LABELS: dict[str, str] = {
    "critical": "CRIT",
    "high": "ALTO",
    "medium": "MED",
    "low": "BAJO",
    "info": "INFO",
}

#: Text fallback per device class, kept for the reports and the exporters,
#: which write plain text and cannot carry a drawing. The table draws real
#: pictograms instead (see :mod:`ip_inspector.interface.theme`), because these
#: glyphs are so alike that a desktop, a server and a switch read the same.
DEVICE_TYPE_ICONS: dict[str, str] = {
    "Router": "◈",            # diamond: the thing everything routes through
    "Network Device": "⬢",    # hexagon: switch, AP, bridge
    "IP Camera": "◉",         # bullseye: lens
    "Printer": "▥",           # striped: paper comes out
    "Windows PC": "▣",        # boxed square: a desktop
    "Mac / Apple": "▣",
    "Apple Device": "▣",
    "Linux Server": "▤",      # rack lines
    "Server": "▤",
    "Raspberry Pi": "◆",      # a small board
    "IoT Device": "◆",
    "Mobile / Tablet": "▯",   # a slab
}

#: Shown for anything the classifier could not place.
UNKNOWN_TYPE_ICON = "▫"


def device_type_icon(device_type: str) -> str:
    """The glyph for a device class, never empty."""
    return DEVICE_TYPE_ICONS.get(device_type, UNKNOWN_TYPE_ICON)
