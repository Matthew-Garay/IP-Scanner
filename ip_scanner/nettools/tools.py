"""Network reconnaissance and IT administration tools.

Every tool follows the same contract: it returns a :class:`ToolResult`
instead of raising, so a failing probe never interrupts the UI. Tools that
need an external binary (traceroute, whois) degrade gracefully when that
binary is unavailable.

Implemented with the standard library only, keeping the production
dependency set at four packages.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time

from ..core.models import SubnetInfo, ToolResult, TracerouteHop
from ..core.ping import run_command as _run
from ..core.utils import get_local_proxy_ports, get_running_vpn_processes, get_virtual_adapters

#: Common DNS record types offered in the UI dropdown.
DNS_RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV")


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def dns_lookup(domain: str, record_type: str = "A") -> ToolResult:
    """Resolve a domain, preferring the system resolver and falling back to nslookup."""
    started = time.perf_counter()
    result = ToolResult(name=f"DNS {record_type}: {domain}")

    if not domain.strip():
        result.ok, result.error = False, "Empty domain"
        return result

    record_type = record_type.upper().strip() or "A"
    # A and AAAA are answered directly by the resolver; the rest need nslookup.
    if record_type in ("A", "AAAA"):
        try:
            infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
            addresses = sorted({info[4][0] for info in infos})
            result.lines = addresses
            result.ok = bool(addresses)
            if not addresses:
                result.error = "No records"
        except socket.gaierror as exc:
            result.ok, result.error = False, str(exc)
    else:
        code, stdout, stderr = _run(["nslookup", "-type=" + record_type, domain])
        if code != 0:
            result.ok, result.error = False, stderr.strip() or "nslookup fallo"
        else:
            result.lines = [line.strip() for line in stdout.splitlines() if line.strip()]
            result.ok = True

    result.output = "\n".join(result.lines)
    result.elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
    return result


def reverse_dns(ip: str) -> ToolResult:
    """Reverse-resolve an IP address to its PTR hostname."""
    result = ToolResult(name=f"PTR: {ip}")
    try:
        hostname, aliases, _addresses = socket.gethostbyaddr(ip)
        result.output = hostname
        result.lines = [hostname, *aliases]
        result.ok = True
    except (socket.herror, socket.gaierror, OSError) as exc:
        result.ok, result.error = False, str(exc)
    return result


def zone_transfer(domain: str) -> ToolResult:
    """
    Attempt a DNS zone transfer (AXFR) against the authoritative nameservers.

    A successful transfer is a serious misconfiguration: it hands over the
    full zone file, including internal hostnames and services.
    """
    result = ToolResult(name=f"Zone transfer: {domain}")
    if not domain.strip():
        result.ok, result.error = False, "Empty domain"
        return result

    _code, stdout, _err = _run(["nslookup", "-type=NS", domain], timeout=15.0)
    servers = [line.strip() for line in stdout.splitlines() if line.strip().startswith("NS")]
    if not servers:
        result.ok, result.error = False, "Could not fetch the NS servers"
        return result

    for record in servers:
        code, stdout, _stderr = _run(["nslookup", "-type=AXFR", domain, record], timeout=20.0)
        if code == 0 and "Transfer failed" not in stdout and len(stdout.splitlines()) > 5:
            lines = [line.strip() for line in stdout.splitlines() if line.strip()]
            result.lines = lines
            result.output = "\n".join(lines)
            result.ok = True
            return result

    result.ok = True
    result.output = "Transferencia rechazada (configuracion correcta)"
    result.lines = [result.output]
    return result


def email_security_records(domain: str) -> ToolResult:
    """Retrieve SPF, DMARC and MX records, the baseline of mail security."""
    result = ToolResult(name=f"SPF/DMARC/MX: {domain}")
    if not domain.strip():
        result.ok, result.error = False, "Empty domain"
        return result

    queries = (
        ("SPF (domain TXT)", domain, "TXT"),
        ("DMARC (_dmarc)", f"_dmarc.{domain}", "TXT"),
        ("MTA-STS", f"_mta-sts.{domain}", "TXT"),
        ("MX", domain, "MX"),
    )
    for label, name, record_type in queries:
        lookup = dns_lookup(name, record_type)
        status = lookup.output.strip() if lookup.ok else "no encontrado"
        result.lines.append(f"{label}: {status}")

    result.output = "\n".join(result.lines)
    result.ok = True
    return result


def dns_summary(domain: str) -> ToolResult:
    """
    Compact A / AAAA / NS / MX overview of a domain.

    The address records come from the system resolver and the mail and
    authority records from nslookup, so the panel still shows something
    useful on a host where one of the two is unavailable.
    """
    result = ToolResult(name=f"DNS summary: {domain}")
    if not domain.strip():
        result.ok, result.error = False, "Empty domain"
        return result

    try:
        infos = socket.getaddrinfo(domain, None)
    except (socket.gaierror, UnicodeError, OSError) as exc:
        infos = []
        result.error = str(exc)

    for family, label in ((socket.AF_INET, "A"), (socket.AF_INET6, "AAAA")):
        addresses = sorted({
            info[4][0] for info in infos if info[0] == family
        })
        result.lines.extend(f"  {label:<5} {address}" for address in addresses)

    for record_type in ("NS", "MX"):
        code, stdout, _stderr = _run(
            ["nslookup", "-type=" + record_type, domain], timeout=10.0
        )
        if code != 0:
            continue
        result.lines.extend(
            f"  {record_type:<5} {value}"
            for value in _parse_nslookup_records(stdout, record_type)
        )

    if not result.lines:
        result.ok = False
        result.error = result.error or "No records"
    result.output = "\n".join(result.lines)
    return result


def _parse_nslookup_records(stdout: str, record_type: str) -> list[str]:
    """
    Pull the answer values out of an nslookup response.

    Answer lines look like ``example.com 3600 IN NS ns1.example.com``; the
    value is always the last token.
    """
    values: list[str] = []
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) < 5 or "IN" not in parts or record_type not in parts:
            continue
        value = parts[-1]
        if value not in values:
            values.append(value)
    return values


# ---------------------------------------------------------------------------
# Path and reachability
# ---------------------------------------------------------------------------

def traceroute(target: str, max_hops: int = 20) -> ToolResult:
    """Trace the network path to a host, resolving each hop when possible."""
    result = ToolResult(name=f"Traceroute: {target}")
    if not target.strip():
        result.ok, result.error = False, "Empty target"
        return result

    hops = max(1, min(int(max_hops), 64))
    code, stdout, stderr = _run(["tracert", "-d", "-h", str(hops), "-w", "800", target], timeout=60.0)
    if code == 127:
        code, stdout, stderr = _run(["traceroute", "-n", "-m", str(hops), "-w", "1", target], timeout=60.0)
    if code == 127:
        result.ok, result.error = False, "traceroute is not available on this system"
        return result
    if code not in (0, 1):
        result.ok, result.error = False, stderr.strip() or "tracert fallo"
        return result

    result.hops = parse_traceroute(stdout)
    for hop in result.hops:
        rtt = "/".join(f"{value:.0f}" for value in hop.rtts) or "no reply"
        row = f"  {hop.hop:>2}  {hop.address:<16} {rtt} ms"
        if hop.hostname:
            row += f"   [{hop.hostname}]"
        result.lines.append(row)

    result.output = "\n".join(result.lines)
    result.ok = bool(result.lines)
    if not result.ok:
        result.error = "No hops returned"
    return result


def parse_traceroute(stdout: str) -> list[TracerouteHop]:
    """
    Turn ``tracert`` / ``traceroute`` output into structured hops.

    Kept separate from :func:`traceroute` so the visual view and the console
    pane share one parser and can never disagree about the path.
    """
    hops: list[TracerouteHop] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith(("tracing", "trace route")):
            continue
        hop_match = re.match(r"^(\d+)\s+(.*)$", stripped)
        if not hop_match:
            continue

        remainder = hop_match.group(2)
        address_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", remainder)
        address = address_match.group(0) if address_match else "*"
        # RTT tokens look like "3 ms" or "3/3 ms"; keep the bare numbers.
        times = tuple(float(value) for value in re.findall(r"(\d+)\s*ms", remainder)[:3])

        hostname = ""
        if address != "*":
            try:
                hostname = socket.gethostbyaddr(address)[0]
            except (socket.herror, socket.gaierror, OSError):
                hostname = ""

        hops.append(TracerouteHop(int(hop_match.group(1)), address, hostname, times))
    return hops


def ping_host(host: str, count: int = 4, timeout: float = 2.0) -> ToolResult:
    """Ping a host and report latency, packet loss and the observed TTL."""
    result = ToolResult(name=f"Ping: {host}")
    if not host.strip():
        result.ok, result.error = False, "Empty target"
        return result

    count = max(1, min(int(count), 20))
    code, stdout, stderr = _run(["ping", "-n", str(count), "-w", str(int(timeout * 1000)), host], timeout=count * timeout + 10)
    if code == 127:
        code, stdout, stderr = _run(["ping", "-c", str(count), "-W", str(int(timeout)), host], timeout=count * timeout + 10)
    if code == 127:
        result.ok, result.error = False, "ping is not available on this system"
        return result

    result.output = stdout.strip()
    result.lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    result.ok = code == 0
    if not result.ok:
        result.error = "No reply (host unreachable or blocking ICMP)"
    return result


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

_WHOIS_SERVERS: dict[str, str] = {
    "arin": "whois.arin.net",
    "ripe": "whois.ripe.net",
    "lacnic": "whois.lacnic.net",
    "apnic": "whois.apnic.net",
    "afrinic": "whois.afrinic.net",
}


def whois_lookup(query: str) -> ToolResult:
    """
    Query a WHOIS service for an IP address or domain.

    For IPs the regional registry is selected by first octet so the answer
    comes from the authoritative source instead of a thin aggregator.
    """
    result = ToolResult(name=f"WHOIS: {query}")
    if not query.strip():
        result.ok, result.error = False, "Empty query"
        return result

    query = query.strip()
    server = "whois.iana.org"
    if _looks_like_ip(query):
        address = ipaddress.ip_address(query)
        if address.version == 4:
            server = _whois_server_for_ip(address)

    code, stdout, stderr = _run(["whois", server, query], timeout=20.0)
    if code == 127:
        stdout = _whois_over_tcp(server, query)
        if not stdout:
            result.ok, result.error = False, "whois no disponible (ni comando ni TCP)"
            return result
    elif code != 0:
        result.ok, result.error = False, stderr.strip() or "whois fallo"
        return result

    result.lines = [line.rstrip() for line in stdout.splitlines() if line.strip()]
    result.output = "\n".join(result.lines[:200])
    result.ok = True
    return result


def _whois_server_for_ip(address: ipaddress.IPv4Address) -> str:
    """Pick the regional RIR WHOIS server from the first octet."""
    first = int(str(address).split(".")[0])
    if first < 3:
        return _WHOIS_SERVERS["arin"]
    if first < 72:
        return _WHOIS_SERVERS["arin"]
    if first < 80:
        return _WHOIS_SERVERS["ripe"]
    if first < 85:
        return _WHOIS_SERVERS["ripe"]
    if first < 212:
        return _WHOIS_SERVERS["ripe"]
    if first < 213:
        return _WHOIS_SERVERS["ripe"]
    if first == 203:
        return _WHOIS_SERVERS["apnic"]
    return _WHOIS_SERVERS["arin"]


def _whois_over_tcp(server: str, query: str) -> str:
    """Fallback WHOIS client using a plain TCP socket (RFC 3912)."""
    try:
        with socket.create_connection((server, 43), timeout=10) as connection:
            connection.sendall(f"{query}\r\n".encode())
            chunks: list[bytes] = []
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")
    except OSError:
        return ""


#: Canonical WHOIS field -> the spellings registries use for it. The first
#: spelling found in a response wins, since registries differ in wording.
_WHOIS_FIELD_ALIASES: dict[str, frozenset[str]] = {
    "domain": frozenset({"domain name", "domain", "netname"}),
    "org": frozenset({"org", "organisation", "organization", "orgname", "org-name"}),
    "country": frozenset({"country", "countrycode", "country code"}),
    "created": frozenset({
        "creation date", "created", "created on", "registered on",
        "domain registration date", "registration time",
    }),
    "updated": frozenset({"updated date", "last updated", "last-update", "changed"}),
    "expires": frozenset({
        "registry expiry date", "expiry date", "expiration date",
        "paid-till", "renewal date", "expires",
    }),
    "status": frozenset({"status", "state", "domain status"}),
    "registrar": frozenset({"registrar", "sponsoring registrar", "registrar name"}),
    "abuse": frozenset({"abuse-mailbox", "abuse contact email", "abuse contact", "org-abuse"}),
}

#: Fields that repeat once per entry and are therefore collected together.
_WHOIS_NAME_SERVER_KEYS = frozenset({"nserver", "name server", "nameserver"})


def whois_key_fields(text: str) -> list[tuple[str, str]]:
    """
    Extract the interesting fields from a raw WHOIS response.

    Returns ``(canonical key, value)`` pairs in display order, with the name
    servers joined into a single ``nameservers`` entry. Registries never agree
    on a format, so every known spelling is accepted and anything unknown is
    left to the caller.
    """
    found: dict[str, str] = {}
    name_servers: list[str] = []

    for raw in text.splitlines():
        key, separator, value = raw.partition(":")
        if not separator:
            continue
        key, value = key.strip().lower(), value.strip()
        if not value:
            continue

        if key in _WHOIS_NAME_SERVER_KEYS:
            if value not in name_servers:
                name_servers.append(value)
            continue
        for canonical, aliases in _WHOIS_FIELD_ALIASES.items():
            if key in aliases and canonical not in found:
                found[canonical] = value
                break

    # Display order is the declaration order of the alias mapping.
    fields: list[tuple[str, str]] = [
        (canonical, found[canonical]) for canonical in _WHOIS_FIELD_ALIASES
        if canonical in found
    ]
    if name_servers:
        fields.append(("nameservers", ", ".join(name_servers[:4])))
    return fields


# ---------------------------------------------------------------------------
# Subnet arithmetic
# ---------------------------------------------------------------------------

#: Upper bound on the rows of a split plan, so the table stays readable.
MAX_SUBNET_ROWS = 64


def subnet_details(cidr: str) -> ToolResult:
    """
    Break a CIDR block down into every field the calculator displays.

    The structured record travels in ``result.data``; the console pane keeps
    using the Spanish text produced by :func:`subnet_info`.
    """
    result = ToolResult(name=f"Subred: {cidr}")
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as exc:
        result.ok, result.error = False, str(exc)
        return result

    result.data = _subnet_data(network)
    result.ok = True
    return result


def _subnet_data(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> SubnetInfo:
    """Full arithmetic of one parsed network."""
    total = network.num_addresses
    if network.prefixlen >= network.max_prefixlen - 1:
        # /31 and /32 (or /127 and /128): nothing is reserved as network or
        # broadcast, so every address of the block is usable.
        first = last = network.network_address
        usable = total
    else:
        first = ipaddress.ip_address(int(network.network_address) + 1)
        last = ipaddress.ip_address(int(network.broadcast_address) - 1)
        usable = total - 2

    return SubnetInfo(
        cidr=str(network),
        version=network.version,
        prefixlen=network.prefixlen,
        netmask=str(network.netmask),
        wildcard=_wildcard_mask(network.netmask),
        network=str(network.network_address),
        broadcast=str(network.broadcast_address),
        first_host=str(first),
        last_host=str(last),
        total_addresses=total,
        usable_hosts=usable,
        is_private=network.is_private,
    )


def _wildcard_mask(netmask: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Inverse of the netmask: the form Cisco uses in ACLs."""
    inverted = int(netmask) ^ (2 ** netmask.max_prefixlen - 1)
    # Rebuild through the original class: a small inverted IPv6 value would
    # otherwise be rebuilt as an IPv4 address.
    return str(type(netmask)(inverted))


def split_subnet(cidr: str, count: int = 4) -> ToolResult:
    """
    Divide a block into equal subnets, smallest table first.

    ``count`` is rounded up to the next power of two, because a prefix can
    only be split evenly into a power-of-two number of blocks. The plan
    travels in ``result.data`` as a list of :class:`SubnetInfo`.
    """
    result = ToolResult(name=f"Subnet split: {cidr}")
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as exc:
        result.ok, result.error = False, str(exc)
        return result

    wanted = max(1, min(int(count), MAX_SUBNET_ROWS))
    extra_bits = max(0, (wanted - 1).bit_length())
    target = network.prefixlen + extra_bits
    if target > network.max_prefixlen:
        result.ok, result.error = False, "The block cannot be split any further"
        return result

    blocks = [network] if extra_bits == 0 else network.subnets(new_prefix=target)
    plan: list[SubnetInfo] = []
    for block in blocks:
        details = subnet_details(str(block))
        if details.data is not None:
            plan.append(details.data)   # type: ignore[arg-type]

    result.lines = ["  {:>3}  {:<22} {:<16} {:<16} {:<16} {:>7}".format(
        "#", "Network", "First host", "Last host", "Broadcast", "Usable"
    )]
    for index, info in enumerate(plan, start=1):
        result.lines.append(
            "  {:>3}  {:<22} {:<16} {:<16} {:<16} {:>7}".format(
                index, info.cidr, info.first_host, info.last_host,
                info.broadcast, info.usable_hosts,
            )
        )

    result.output = "\n".join(result.lines)
    result.data = plan
    result.ok = True
    return result


def subnet_info(cidr: str) -> ToolResult:
    """Break a CIDR block down into mask, range, broadcast and usable count."""
    details = subnet_details(cidr)
    if not details.ok:
        return details

    info = details.data
    first_host = last_host = "-"
    if info.usable_hosts != info.total_addresses:   # /31 and /32 keep both
        first_host, last_host = info.first_host, info.last_host

    lines = [
        f"Network      : {info.network}/{info.prefixlen}",
        f"Netmask      : {info.netmask}",
        f"First host   : {first_host}",
        f"Last host    : {last_host}",
        f"Broadcast    : {info.broadcast}",
        f"Addresses    : {info.total_addresses}",
        f"Usable       : {info.usable_hosts}",
        f"Type         : {'private' if info.is_private else 'public'}",
    ]
    details.lines = lines
    details.output = "\n".join(lines)
    return details


def ip_in_network(ip: str, cidr: str) -> ToolResult:
    """Check whether an address falls inside a CIDR block."""
    result = ToolResult(name=f"Membership: {ip} in {cidr}")
    try:
        address = ipaddress.ip_address(ip.strip())
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as exc:
        result.ok, result.error = False, str(exc)
        return result

    inside = address.version == network.version and address in network
    result.output = "YES" if inside else "NO"
    result.lines = [f"{ip} {'belongs to' if inside else 'does NOT belong to'} {network}"]
    result.ok = True
    return result


# ---------------------------------------------------------------------------
# Local exposure
# ---------------------------------------------------------------------------
def local_exposure_report() -> ToolResult:
    """Summarise VPN adapters, proxy ports and listening services on this host."""
    result = ToolResult(name="Local exposure")
    adapters = get_virtual_adapters()
    processes = get_running_vpn_processes()
    proxies = get_local_proxy_ports()

    lines = ["Virtual adapters:"]
    lines.extend([f"  - {name}" for name in adapters] or ["  (none)"])
    lines.append("VPN/proxy processes:")
    lines.extend([f"  - {name}" for name in processes] or ["  (none)"])
    lines.append("Listening proxy ports:")
    lines.extend([f"  - {port}/tcp  {label}" for port, label in proxies.items()] or ["  (none)"])

    result.lines = lines
    result.output = "\n".join(lines)
    result.ok = True
    return result


def listening_ports() -> ToolResult:
    """List the TCP ports this machine is currently listening on."""
    result = ToolResult(name="Listening ports")
    try:
        import psutil

        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, RuntimeError, OSError) as exc:
        result.ok, result.error = False, f"Could not read the connections: {exc}"
        return result

    seen: set[tuple[str, int]] = set()
    for connection in connections:
        if connection.status != psutil.CONN_LISTEN or not connection.laddr:
            continue
        host, port = connection.laddr[0], connection.laddr[1]
        if port and (host, port) not in seen:
            seen.add((host, port))
            result.lines.append(f"  {host}:{port}/tcp")

    if not result.lines:
        result.lines = ["  (none)"]
    result.output = "\n".join(result.lines)
    result.ok = True
    return result

# ---------------------------------------------------------------------------
# Host checks: ports, TLS, HTTP headers
# ---------------------------------------------------------------------------
def port_check(host: str, ports: tuple[int, ...], timeout: float = 0.8,
               workers: int = 400) -> ToolResult:
    """TCP-connect probe of an explicit port list on a single host."""
    from concurrent.futures import ThreadPoolExecutor

    from ..core.models import KNOWN_SERVICES

    host = host.strip()
    result = ToolResult(name=f"Port check: {host}")
    if not host:
        result.ok, result.error = False, "Empty target"
        return result
    if not ports:
        result.ok, result.error = False, "No ports to probe"
        return result
    try:
        address = socket.gethostbyname(host)
    except (socket.gaierror, UnicodeError) as exc:
        result.ok, result.error = False, f"Cannot resolve {host}: {exc}"
        return result

    started = time.perf_counter()

    def probe(port: int) -> tuple[int, str, float | None]:
        begun = time.perf_counter()
        try:
            with socket.create_connection((address, port), timeout=timeout):
                return port, "open", (time.perf_counter() - begun) * 1000
        except ConnectionRefusedError:
            return port, "closed", None
        except OSError:
            return port, "filtered", None

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(ports)))) as pool:
        outcomes = list(pool.map(probe, ports))

    opened = [item for item in outcomes if item[1] == "open"]
    closed = sum(1 for item in outcomes if item[1] == "closed")
    filtered = len(outcomes) - len(opened) - closed
    result.lines = [f"Target: {host} ({address})",
                    f"{'PORT':<10}{'STATE':<10}{'SERVICE':<16}LATENCY"]
    for port, state, latency in opened:
        service = KNOWN_SERVICES.get(port, "")
        result.lines.append(
            f"{str(port) + '/tcp':<10}{state:<10}{service:<16}{latency:.1f} ms")
    if not opened:
        result.lines.append("(no open ports)")
    result.lines.append(f"{len(opened)} open, {closed} closed, {filtered} filtered "
                        f"out of {len(outcomes)} probed")
    result.elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
    result.output = "\n".join(result.lines)
    result.data = [port for port, *_rest in opened]
    return result


def tls_check(host: str, port: int = 443) -> ToolResult:
    """Certificate, protocol and cipher of a TLS endpoint."""
    from ..analysis.audit import inspect_tls

    host = host.strip()
    result = ToolResult(name=f"TLS: {host}:{port}")
    if not host:
        result.ok, result.error = False, "Empty target"
        return result
    report = inspect_tls(host, port)
    if not report.supported:
        result.ok, result.error = False, report.error or "No TLS handshake"
        return result
    days = report.days_remaining if report.days_remaining is not None else "-"
    result.lines = [
        f"Protocol     : {report.protocol}",
        f"Cipher       : {report.cipher}",
        f"Subject      : {report.subject or '-'}",
        f"Issuer       : {report.issuer or '-'}",
        f"Valid from   : {report.not_before or '-'}",
        f"Valid until  : {report.not_after or '-'}",
        f"Days left    : {days}",
        f"Alt names    : {', '.join(report.subject_alt_names[:10]) or '-'}",
    ]
    issues = [item for item in report.findings if not item.startswith("Issued by")]
    result.lines.append("Findings     : " + ("; ".join(issues) if issues else "none"))
    result.output = "\n".join(result.lines)
    return result


def http_headers(url: str) -> ToolResult:
    """Status, server banner and missing security headers of a URL."""
    from ..analysis.audit import audit_http

    url = url.strip()
    result = ToolResult(name=f"HTTP headers: {url}")
    if not url:
        result.ok, result.error = False, "Empty URL"
        return result
    report = audit_http(url)
    if report.error and report.status_code is None:
        result.ok, result.error = False, report.error
        return result
    result.lines = [
        f"URL          : {report.url}",
        f"Status       : {report.status_code}",
        f"Server       : {report.server or '-'}",
        f"Time         : {report.elapsed_ms} ms",
        "",
        "Response headers:",
    ]
    result.lines += [f"  {key}: {value}" for key, value in list(report.headers.items())[:40]]
    result.lines += ["", "Security findings:"]
    result.lines += ([f"  [{severity.upper()}] {text}" for severity, text in report.findings]
                     or ["  none"])
    result.output = "\n".join(result.lines)
    return result


# ---------------------------------------------------------------------------
# Local machine
# ---------------------------------------------------------------------------
def _ip_sort_key(value: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in value.split("."))
    except ValueError:
        return (999,)


def arp_table() -> ToolResult:
    """The operating system's neighbour (ARP) cache, with vendors."""
    from ..core.utils import lookup_vendor, read_arp_cache

    result = ToolResult(name="ARP table")
    try:
        cache = read_arp_cache()
    except Exception as exc:  # noqa: BLE001 - platform specific failure
        result.ok, result.error = False, str(exc)
        return result
    result.lines = [f"{'IP':<18}{'MAC':<20}VENDOR"]
    for ip in sorted(cache, key=_ip_sort_key):
        result.lines.append(f"{ip:<18}{cache[ip]:<20}{lookup_vendor(cache[ip]) or '-'}")
    if len(result.lines) == 1:
        result.lines.append("(empty)")
    result.output = "\n".join(result.lines)
    return result


def local_adapters() -> ToolResult:
    """Local network interfaces with address, network and gateway."""
    from ..core.utils import default_gateway, list_adapters

    result = ToolResult(name="Network adapters")
    for adapter in list_adapters():
        if not adapter.address:
            continue
        state = "up" if adapter.is_up else "down"
        kind = "virtual" if adapter.is_virtual else "physical"
        result.lines.append(adapter.name)
        result.lines.append(f"  address  : {adapter.address} / {adapter.netmask}")
        result.lines.append(f"  network  : {adapter.network or '-'}  ({state}, {kind})")
        if adapter.is_scannable:
            result.lines.append(f"  scan     : {adapter.sweep_range}")
    result.lines.append(f"Default gateway: {default_gateway() or '-'}")
    result.output = "\n".join(result.lines)
    return result


def wake_on_lan(mac: str) -> ToolResult:
    """Broadcast a Wake-on-LAN magic packet to a MAC address."""
    from ..actions.wol import send_wol

    mac = mac.strip()
    result = ToolResult(name=f"Wake-on-LAN: {mac}")
    try:
        sent = send_wol(mac)
    except ValueError:
        result.ok, result.error = False, f"'{mac}' is not a valid MAC address"
        return result
    except OSError as exc:
        result.ok, result.error = False, str(exc)
        return result
    result.ok = sent > 0
    result.output = (f"Magic packet broadcast to {mac}" if result.ok
                     else "The broadcast could not be sent from this adapter")
    result.lines = [result.output]
    if not result.ok:
        result.error = result.output
    return result


# ---------------------------------------------------------------------------
# Windows shares
# ---------------------------------------------------------------------------
def parse_net_view(stdout: str) -> list[tuple[str, str, str]]:
    """
    Shares from ``net view \\\\host`` output, as (name, type, comment).

    The output is localised ("Share name  Type  Used as  Comment" in English,
    "Nombre de recurso compartido  Tipo ..." in Spanish) but always laid out
    in fixed columns under a dashed rule, so the column starts are read from
    the header line instead of matching words.
    """
    lines = stdout.splitlines()
    try:
        rule = next(i for i, line in enumerate(lines) if set(line.strip()) == {"-"}
                    and len(line.strip()) > 20)
    except StopIteration:
        return []
    # The header is the last non-blank line above the rule (Windows puts an
    # empty line between them).
    header = next((line for line in reversed(lines[:rule]) if line.strip()), "")
    starts = [0] + [m.end() for m in re.finditer(r"\S\s{2,}(?=\S)", header)]
    shares: list[tuple[str, str, str]] = []
    for line in lines[rule + 1:]:
        if not line.strip():
            continue
        # The closing "The command completed successfully." line has no
        # column gaps; a real row always does.
        if not re.search(r"\S\s{2,}\S", line):
            break
        cells = [line[a:b].strip() for a, b in zip(starts, starts[1:] + [len(line)])]
        name = cells[0] if cells else ""
        kind = cells[1] if len(cells) > 1 else ""
        comment = cells[-1] if len(cells) > 3 else ""
        if name:
            shares.append((name, kind, comment))
    return shares


def list_shares(host: str) -> ToolResult:
    """Folders and printers a Windows/SMB host shares (``net view``)."""
    host = host.strip().lstrip("\\")
    result = ToolResult(name=f"Shared folders: {host}")
    if not host:
        result.ok, result.error = False, "Empty target"
        return result
    code, stdout, stderr = _run(["net", "view", f"\\\\{host}"], timeout=20.0)
    if code == 127:
        result.ok, result.error = False, "net.exe is not available on this system"
        return result
    shares = parse_net_view(stdout)
    result.data = shares
    if code != 0 and not shares:
        message = (stderr or stdout).strip().splitlines()
        result.ok = False
        result.error = (message[-1] if message else f"net view failed ({code})") + \
            " — the host may not share anything, or needs credentials."
        return result
    result.lines = [f"{'SHARE':<24}{'TYPE':<10}COMMENT"]
    result.lines += [f"{name:<24}{kind:<10}{comment}" for name, kind, comment in shares]
    if not shares:
        result.lines.append("(no shared folders)")
    result.output = "\n".join(result.lines)
    return result
