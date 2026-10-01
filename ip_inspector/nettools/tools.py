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
        result.ok, result.error = False, "Dominio vacio"
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
                result.error = "Sin registros"
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
        result.ok, result.error = False, "Dominio vacio"
        return result

    _code, stdout, _err = _run(["nslookup", "-type=NS", domain], timeout=15.0)
    servers = [line.strip() for line in stdout.splitlines() if line.strip().startswith("NS")]
    if not servers:
        result.ok, result.error = False, "No se pudieron obtener los servidores NS"
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
        result.ok, result.error = False, "Dominio vacio"
        return result

    queries = (
        ("SPF (TXT del dominio)", domain, "TXT"),
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
    result = ToolResult(name=f"Resumen DNS: {domain}")
    if not domain.strip():
        result.ok, result.error = False, "Dominio vacio"
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
        result.error = result.error or "Sin registros"
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
        result.ok, result.error = False, "Destino vacio"
        return result

    hops = max(1, min(int(max_hops), 64))
    code, stdout, stderr = _run(["tracert", "-d", "-h", str(hops), "-w", "800", target], timeout=60.0)
    if code == 127:
        code, stdout, stderr = _run(["traceroute", "-n", "-m", str(hops), "-w", "1", target], timeout=60.0)
    if code == 127:
        result.ok, result.error = False, "traceroute no disponible en este sistema"
        return result
    if code not in (0, 1):
        result.ok, result.error = False, stderr.strip() or "tracert fallo"
        return result

    result.hops = parse_traceroute(stdout)
    for hop in result.hops:
        rtt = "/".join(f"{value:.0f}" for value in hop.rtts) or "sin respuesta"
        row = f"  {hop.hop:>2}  {hop.address:<16} {rtt} ms"
        if hop.hostname:
            row += f"   [{hop.hostname}]"
        result.lines.append(row)

    result.output = "\n".join(result.lines)
    result.ok = bool(result.lines)
    if not result.ok:
        result.error = "Sin saltos devueltos"
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
        result.ok, result.error = False, "Destino vacio"
        return result

    count = max(1, min(int(count), 20))
    code, stdout, stderr = _run(["ping", "-n", str(count), "-w", str(int(timeout * 1000)), host], timeout=count * timeout + 10)
    if code == 127:
        code, stdout, stderr = _run(["ping", "-c", str(count), "-W", str(int(timeout)), host], timeout=count * timeout + 10)
    if code == 127:
        result.ok, result.error = False, "ping no disponible"
        return result

    result.output = stdout.strip()
    result.lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    result.ok = code == 0
    if not result.ok:
        result.error = "Sin respuesta (host inaccesible o bloquea ICMP)"
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
        result.ok, result.error = False, "Consulta vacia"
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
    result = ToolResult(name=f"Division de subred: {cidr}")
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as exc:
        result.ok, result.error = False, str(exc)
        return result

    wanted = max(1, min(int(count), MAX_SUBNET_ROWS))
    extra_bits = max(0, (wanted - 1).bit_length())
    target = network.prefixlen + extra_bits
    if target > network.max_prefixlen:
        result.ok, result.error = False, "El bloque ya no se puede dividir mas"
        return result

    blocks = [network] if extra_bits == 0 else network.subnets(new_prefix=target)
    plan: list[SubnetInfo] = []
    for block in blocks:
        details = subnet_details(str(block))
        if details.data is not None:
            plan.append(details.data)   # type: ignore[arg-type]

    result.lines = ["  {:>3}  {:<22} {:<16} {:<16} {:<16} {:>7}".format(
        "#", "Red", "Primer host", "Ultimo host", "Broadcast", "Usables"
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
        f"Red          : {info.network}/{info.prefixlen}",
        f"Mascara      : {info.netmask}",
        f"Primer host  : {first_host}",
        f"Ultimo host  : {last_host}",
        f"Broadcast    : {info.broadcast}",
        f"Direcciones  : {info.total_addresses}",
        f"Usables      : {info.usable_hosts}",
        f"Tipo         : {'privada' if info.is_private else 'publica'}",
    ]
    details.lines = lines
    details.output = "\n".join(lines)
    return details


def ip_in_network(ip: str, cidr: str) -> ToolResult:
    """Check whether an address falls inside a CIDR block."""
    result = ToolResult(name=f"Contencion: {ip} en {cidr}")
    try:
        address = ipaddress.ip_address(ip.strip())
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as exc:
        result.ok, result.error = False, str(exc)
        return result

    inside = address.version == network.version and address in network
    result.output = "SI" if inside else "NO"
    result.lines = [f"{ip} {'pertenece a' if inside else 'NO pertenece a'} {network}"]
    result.ok = True
    return result


# ---------------------------------------------------------------------------
# Local exposure
# ---------------------------------------------------------------------------
def local_exposure_report() -> ToolResult:
    """Summarise VPN adapters, proxy ports and listening services on this host."""
    result = ToolResult(name="Exposicion local")
    adapters = get_virtual_adapters()
    processes = get_running_vpn_processes()
    proxies = get_local_proxy_ports()

    lines = ["Adaptadores virtuales:"]
    lines.extend(f"  - {name}" for name in adapters) or ["  (ninguno)"]
    lines.append("Procesos VPN/proxy:")
    lines.extend(f"  - {name}" for name in processes) or ["  (ninguno)"]
    lines.append("Puertos proxy en escucha:")
    lines.extend(f"  - {port}/tcp  {label}" for port, label in proxies.items()) or ["  (ninguno)"]

    result.lines = lines
    result.output = "\n".join(lines)
    result.ok = True
    return result


def listening_ports() -> ToolResult:
    """List the TCP ports this machine is currently listening on."""
    result = ToolResult(name="Puertos en escucha")
    try:
        import psutil

        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, RuntimeError, OSError) as exc:
        result.ok, result.error = False, f"No se pudieron leer las conexiones: {exc}"
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
        result.lines = ["  (ninguno)"]
    result.output = "\n".join(result.lines)
    result.ok = True
    return result