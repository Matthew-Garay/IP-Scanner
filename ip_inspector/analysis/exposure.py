"""
Offline exposure heuristics for a scanned host.

:mod:`audit` answers *"what does this service say when I connect to it"*.
This module answers the question that matters first, while the sweep is
still running: **given this list of open ports, what is the obvious next
move for an attacker, and how much does it matter on this address?**

Two ideas drive the rules:

*Scope.* The same open port means very different things on ``192.168.1.10``
and on ``203.0.113.7``. Everything reachable from the internet is one
severity step worse than the same service inside the LAN, and that step is
applied here, centrally, instead of being re-decided per rule.

*Combinations.* Individually harmless ports become dangerous in company: a
host answering both SMB and RDP is a two-step remote takeover, and Telnet on
a machine that already runs SSH is simply an oversight.

Everything is derived from what the scan already collected, so a whole sweep
is evaluated instantly, with no second round of packets.
"""

from __future__ import annotations

import ipaddress

from .audit import RISKY_PORTS, _SEVERITY_WEIGHTS
from ..core.models import Device, SecurityFinding, Severity

#: Where an address sits, which decides how exposed a service really is.
SCOPE_PRIVATE = "private"
SCOPE_PUBLIC = "public"
SCOPE_CGNAT = "cgnat"
SCOPE_LINK_LOCAL = "link_local"
SCOPE_LOOPBACK = "loopback"
SCOPE_RESERVED = "reserved"
SCOPE_UNKNOWN = "unknown"

#: Address block shared by carrier NAT equipment, not routable on the internet.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")

#: One severity step, used to escalate everything on a public address.
_ESCALATION: dict[str, Severity] = {
    "info": "low", "low": "medium", "medium": "high", "high": "critical",
    "critical": "critical",
}

#: Ports that hand out a remote interactive session.
REMOTE_ADMIN_PORTS: tuple[int, ...] = (22, 3389, 5900, 5901)

#: The same set plus Telnet: on embedded gear it *is* the admin interface,
#: which is what makes a camera answering on 23 worth its own line.
ADMIN_PORTS: tuple[int, ...] = REMOTE_ADMIN_PORTS + (23,)

#: Legacy Windows name service. Harmless on its own, but it is the transport
#: every SMB worm has ever used, so its mere presence is worth a line.
LEGACY_PORTS: tuple[int, ...] = (139,)

#: Severity for a port that is reported but has no entry in ``RISKY_PORTS``.
_UNRATED_SEVERITY: Severity = "medium"

#: Why each port matters, as a catalogue key. Ports absent from this table
#: fall back to the generic wording and to the description in ``RISKY_PORTS``.
_REASON_KEYS: dict[int, str] = {
    21: "exp.reason.ftp",
    22: "exp.reason.ssh",
    23: "exp.reason.telnet",
    69: "exp.reason.tftp",
    139: "exp.reason.netbios",
    445: "exp.reason.smb",
    512: "exp.reason.rsh",
    513: "exp.reason.rsh",
    514: "exp.reason.syslog",
    873: "exp.reason.rsync",
    1080: "exp.reason.proxy",
    2049: "exp.reason.nfs",
    3306: "exp.reason.db",
    3389: "exp.reason.rdp",
    5432: "exp.reason.db",
    5900: "exp.reason.vnc",
    6379: "exp.reason.cache",
    9200: "exp.reason.db",
    11211: "exp.reason.cache",
    27017: "exp.reason.db",
}

#: Device classes where a reachable admin port is the whole ball game.
_GATEWAY_TYPES = frozenset({"Router", "Network Device"})
_EXPOSED_TYPES = frozenset({"IP Camera", "IoT Device", "Network Device"})


def _finding(
    device: Device,
    severity: Severity,
    title_key: str,
    detail_key: str,
    title: str,
    detail: str,
    **params: object,
) -> SecurityFinding:
    """Build a finding bound to ``device`` and ready to be localised."""
    return SecurityFinding(
        severity, title, detail, device.ip_address,
        title_key=title_key, detail_key=detail_key, params=params,
    )


def _port_finding(device: Device, port: int, scope: str) -> SecurityFinding | None:
    """
    One finding per risky port, escalated when the address is public.

    SSH is reported here even though it is not in ``RISKY_PORTS``: an open
    remote shell is worth a line of its own, and the contextual rules below
    decide how much it matters on this particular device.
    """
    entry = RISKY_PORTS.get(port)
    if entry is None and port not in REMOTE_ADMIN_PORTS + LEGACY_PORTS:
        return None

    severity: Severity = entry[0] if entry else _UNRATED_SEVERITY
    description = entry[1] if entry else ""
    if scope == SCOPE_PUBLIC:
        severity = _bump(severity)

    public = scope == SCOPE_PUBLIC
    return _finding(
        device, severity,
        "exp.title.port_public" if public else "exp.title.port",
        _REASON_KEYS.get(port, "exp.reason.other"),
        f"Port {port} open ({'public address' if public else 'host'})",
        description or f"Port {port} is listening.",
        port=port, reason=description, scope=scope,
    )


def _device_type_finding(device: Device, ports: set[int], scope: str) -> SecurityFinding | None:
    """A remote admin port on the box that routes or watches the network."""
    admin = sorted(ports & set(ADMIN_PORTS))
    if not admin:
        return None

    if device.device_type in _GATEWAY_TYPES:
        key, severity = "exp.admin.gateway", "high"
    elif device.device_type in _EXPOSED_TYPES:
        key, severity = "exp.admin.exposed", "high"
    else:
        return None

    listed = ", ".join(str(port) for port in admin)
    if scope == SCOPE_PUBLIC:
        severity = _bump(severity)
    return _finding(
        device, severity, key + ".title", key + ".detail",
        f"Remote administration on a {device.device_type.lower()}",
        f"Ports {listed} accept remote sessions.",
        ports=listed, device_type=device.device_type,
    )


def _combinations(device: Device, ports: set[int], scope: str) -> list[SecurityFinding]:
    """Rules about port *combinations*, which no single-port rule can see."""
    found: list[SecurityFinding] = []

    if 22 in ports and 23 in ports:
        found.append(_finding(
            device, _bump("high") if scope == SCOPE_PUBLIC else "high",
            "exp.combo.telnet_ssh.title", "exp.combo.telnet_ssh.detail",
            "Telnet open despite SSH",
            "Telnet is still enabled although SSH is available: the obsolete "
            "path is the one an attacker tries first.",
            ports=device.ports_summary,
        ))

    if 445 in ports and 139 in ports:
        found.append(_finding(
            device, _bump("high") if scope == SCOPE_PUBLIC else "high",
            "exp.combo.netbios.title", "exp.combo.netbios.detail",
            "SMB with legacy NetBIOS",
            "SMB is served together with the legacy NetBIOS session service, "
            "which keeps the old attack surface alive.",
            ports=device.ports_summary,
        ))

    if 445 in ports and 3389 in ports:
        found.append(_finding(
            device, "critical",
            "exp.combo.smb_rdp.title", "exp.combo.smb_rdp.detail",
            "SMB and RDP open together",
            "A stolen credential gets file access over SMB first and an "
            "interactive session over RDP second, which is a complete remote "
            "takeover.",
            ports=device.ports_summary,
        ))

    return found


def _public_host_finding(device: Device, ports: set[int], scope: str) -> SecurityFinding | None:
    """
    One umbrella alert for a routable address with anything worth attacking.

    The per-port findings already say *which* service; this one states the
    thing the operator has to act on, which is the address itself.
    """
    if scope != SCOPE_PUBLIC:
        return None
    if not ports & (set(RISKY_PORTS) | set(REMOTE_ADMIN_PORTS) | set(LEGACY_PORTS)):
        return None
    return _finding(
        device, "high", "exp.public.title", "exp.public.detail",
        "Public address with management services exposed",
        "Every service listed here is reachable from the internet.",
        ports=device.ports_summary,
    )


def exposure_findings(device: Device, scope: str | None = None) -> list[SecurityFinding]:
    """
    Evaluate a scanned device against the exposure rules.

    ``scope`` overrides the address classification, which is what lets the
    tests exercise every branch without needing real public addresses. The
    result is sorted worst-first, so ``findings[0]`` is the headline.
    """
    ports = {port.number for port in device.open_ports if port.is_open}
    if not ports:
        return []

    scope = scope or ip_scope(device.ip_address)
    findings: list[SecurityFinding] = []
    for port in sorted(ports):
        finding = _port_finding(device, port, scope)
        if finding is not None:
            findings.append(finding)

    device_finding = _device_type_finding(device, ports, scope)
    if device_finding is not None:
        findings.append(device_finding)

    findings.extend(_combinations(device, ports, scope))

    umbrella = _public_host_finding(device, ports, scope)
    if umbrella is not None:
        findings.append(umbrella)

    return sorted(findings, key=lambda item: item.sort_weight)


def exposure_score(device: Device) -> int:
    """
    Risk score of a device from its exposure findings.

    Same 0-100 scale as :func:`audit.risk_score`, so the Risk column and the
    audit tab cannot disagree about the same host.
    """
    return min(100, sum(
        _SEVERITY_WEIGHTS.get(finding.severity, 0)
        for finding in exposure_findings(device)
    ))

def ip_scope(address: str) -> str:
    """
    Classify an address into one of the ``SCOPE_*`` buckets.

    ``is_private`` alone is not enough: it lumps loopback, link-local and
    CGNAT in with RFC 1918, and those three are not reachable from the
    internet even though ``is_private`` says they are.
    """
    try:
        ip = ipaddress.ip_address(address.strip())
    except ValueError:
        return SCOPE_UNKNOWN

    if ip.is_loopback:
        return SCOPE_LOOPBACK
    if ip.is_link_local:
        return SCOPE_LINK_LOCAL
    if ip.version == 4 and ip in _CGNAT:
        return SCOPE_CGNAT
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return SCOPE_RESERVED
    # ``is_global`` is the question that matters here: a documentation range
    # such as 203.0.113.0/24 is "private" to Python's registry but is not
    # reachable from the internet either, and neither is RFC 1918.
    return SCOPE_PUBLIC if ip.is_global else SCOPE_PRIVATE


def _bump(severity: Severity) -> Severity:
    return _ESCALATION.get(severity, severity)
