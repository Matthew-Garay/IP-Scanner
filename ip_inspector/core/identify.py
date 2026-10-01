"""Device model identification.

The OUI only records a vendor, never a model, so the model has to come
from the device itself. Two cheap sources are available on a LAN without
extra dependencies:

1. **HTTP fingerprinting** - most routers, printers, cameras and NAS units
   expose an admin interface whose ``Server`` header or page ``<title>``
   names the product.
2. **Hostname heuristics** - site hostnames frequently embed the model
   (``hp-laserjet-m404``, ``rwxr01``, ``IPC-HFW2431S``).

Both are best-effort: when nothing matches the model stays empty rather
than guessing something wrong.
"""

from __future__ import annotations

import re
import socket
import time
import urllib.error
import urllib.request

#: Ports worth probing for a device identity.
IDENTITY_PORTS = (80, 8080, 443, 8000)

#: Paths to try on the web interface; many devices answer on a sub-path.
IDENTITY_PATHS = ("/", "/index.html", "/login.html", "/status", "/Info")

#: Generic hostnames tokens that describe the role, not the model.
_GENERIC_TOKENS = frozenset({
    "pc", "printer", "print", "host", "srv", "server", "wkst", "nb",
    "laptop", "desktop", "pc", "pcpc", "client", "user", "admin", "device",
    "cam", "camera", "ipc", "nvr", "dvr", "router", "gw", "modem", "ap",
    "switch", "net", "lan", "wan", "wlan", "wifi", "eth", "en", "es",
})

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_TAG_STRIP = re.compile(r"<[^>]+>")

#: Vendor name fragments that imply a model family even without a title.
_VENDOR_MODEL_HINTS: tuple[tuple[str, str], ...] = (
    ("hewlett", "HP"),
    ("epson", "EPSON"),
    ("xerox", "Xerox"),
    ("canon", "Canon"),
    ("brother", "Brother"),
    ("lexmark", "Lexmark"),
    ("ricoh", "Ricoh"),
    ("konica", "Konica Minolta"),
    ("seiko", "EPSON"),
    ("zhejiang dahua", "Dahua"),
    ("hikvision", "Hikvision"),
    ("axis", "Axis"),
    ("ubiquiti", "UniFi"),
    ("tp-link", "TP-Link"),
    ("mikrotik", "MikroTik"),
    ("raspberry", "Raspberry Pi"),
    ("cisco", "Cisco"),
    ("d-link", "D-Link"),
    ("netgear", "Netgear"),
)


def _clean(text: str) -> str:
    """Flatten a title/header into a single readable line."""
    stripped = _TAG_STRIP.sub(" ", text)
    return re.sub(r"\s+", " ", stripped).strip(" -_|")[:70]


# ---------------------------------------------------------------------------
# Banner grabbing
# ---------------------------------------------------------------------------

#: Services that speak first. Connecting is the whole request: SSH, FTP,
#: SMTP and the mail retrieval protocols all greet the client unprompted, so
#: the version costs nothing beyond the connect the scan already paid for.
#: Telnet is included because it opens with IAC option negotiation, which is
#: proof of life even when it never names itself.
BANNER_PORTS = frozenset({21, 22, 23, 25, 80, 110, 143, 443, 587, 8000,
                          993, 995, 3306, 5432, 6379, 8080, 8081, 11211})

#: A web server says nothing until it is asked, so the smallest question
#: that forces a ``Server:`` header is sent. HTTP/1.0 with no keep-alive
#: closes cleanly on its own and needs no second exchange.
_HTTP_PROBE = (
    b"HEAD / HTTP/1.0\r\nHost: probe\r\n"
    b"User-Agent: ip-inspector\r\nAccept: */*\r\n\r\n"
)

#: Services that stay silent until spoken to, with the smallest thing that
#: makes them talk. Everything else is left alone: sending junk at a device
#: that was only asked "is this port open" is not worth the side effects.
BANNER_PROBES: dict[int, bytes] = {
    80: _HTTP_PROBE,
    8080: _HTTP_PROBE,
    6379: b"PING\r\n",          # Redis answers +PONG
    11211: b"version\r\n",      # memcached states its build
}

#: Ports whose reply is an HTTP response, summarised rather than dumped.
HTTP_PORTS = frozenset({80, 8080, 8000, 8081})

#: Bytes to read and how long to wait for them.
BANNER_BYTES = 200
BANNER_GRACE = 0.4

#: Version patterns per service. Each captures the part an operator would
#: quote in a report: the release, not the whole identification string.
_VERSION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ssh", re.compile(r"SSH-[\d.]+-OpenSSH[_-](\S+)", re.IGNORECASE)),
    ("ssh", re.compile(r"SSH-[\d.]+-(\S+)")),                 # Dropbear and friends
    ("apache", re.compile(r"Apache/([\d.]+[^\s(]*)", re.IGNORECASE)),
    ("nginx", re.compile(r"nginx/([\d.]+)", re.IGNORECASE)),
    ("iis", re.compile(r"Microsoft-IIS/([\d.]+)", re.IGNORECASE)),
    ("proftpd", re.compile(r"ProFTPD ([\d.]+)", re.IGNORECASE)),
    ("vsftpd", re.compile(r"vsFTPd\s+([\d.]+)", re.IGNORECASE)),
    ("mysql", re.compile(r"([\d.]+)-MariaDB", re.IGNORECASE)),
    ("samba", re.compile(r"Samba\s+(\S+)", re.IGNORECASE)),
    ("cups", re.compile(r"CUPS/([\d.]+)", re.IGNORECASE)),
    # Last resort, and deliberately narrow: the product name has to be right
    # there in front of the number. A looser rule happily reads the address
    # out of "220 ready [::ffff:192.168.1.1]" and reports it as a version.
    ("generic", re.compile(r"[A-Za-z][\w.-]*[\s/-]*v?(\d+\.\d+(?:\.\d+)*[A-Za-z0-9._-]*)")),
)


def clean_banner(data: bytes) -> str:
    """
    Turn a raw greeting into one readable line.

    Banners carry binary: MySQL starts with a length byte and a protocol
    version, SSH carries a key exchange list. Decoding as Latin-1 and
    dropping control characters keeps whatever text is there instead of
    failing on the bytes around it.
    """
    text = data.decode("latin-1", errors="replace")
    # NetBIOS-style names and escape codes would otherwise leak into the cell.
    text = "".join(char if char.isprintable() else " " for char in text)
    return re.sub(r"\s+", " ", text).strip()[:BANNER_BYTES]


_STATUS_LINE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})")
_SERVER_HEADER = re.compile(r"^Server:\s*(.+)$", re.IGNORECASE | re.MULTILINE)


def summarise_banner(data: bytes, port: int) -> str:
    """
    One readable line out of whatever the service said.

    An HTTP reply is many lines long and mostly headers nobody asked for, so
    only the status and the ``Server`` line survive. Everything else keeps
    its own text, which is the whole banner for the services that speak
    first.
    """
    if port not in HTTP_PORTS:
        return clean_banner(data)

    # Parsed before cleaning: clean_banner folds the response into a single
    # line, and a "Server:" header that is no longer at the start of one is
    # invisible to a per-line pattern.
    text = data.decode("latin-1", errors="replace")
    status = _STATUS_LINE.search(text)
    server = _SERVER_HEADER.search(text)
    if not (status or server):
        return clean_banner(data)

    parts = []
    if status:
        parts.append(f"HTTP {status.group(1)}")
    if server:
        parts.append(" ".join(server.group(1).split())[:80])
    return " - ".join(parts)



def service_version(banner: str) -> str:
    """
    The release number inside a banner, or "" when it names no version.

    The service-specific patterns run first; the generic one is a last resort
    that would happily quote an IP address, so it is tried last.
    """
    for _name, pattern in _VERSION_PATTERNS:
        found = pattern.search(banner)
        if found:
            return found.group(1).strip(";,)")
    return ""


def os_from_fingerprint(
    ttl: int | None,
    window: int | None = None,
    ports: tuple[int, ...] | list[int] = (),
    vendor: str = "",
) -> str:
    """
    Guess the operating system from how the host answers.

    The TTL is the strongest signal, because the initial value is fixed per
    family and only counts down from there: Windows starts at 128, most
    Unix-like systems and Apple devices at 64, and routers, switches and
    printers commonly at 255. The TCP window only breaks ties, since the
    values overlap heavily between stacks.

    Returns an empty string rather than a guess when there is nothing to
    read: a wrong OS label in an audit is worse than a blank one.
    """
    ports = set(ports)
    if 9100 in ports or 515 in ports or 631 in ports:
        return "Print device"
    if {554, 37777, 8000, 34567} & ports and vendor:
        return ""                       # a camera, not an operating system
    if ttl is None:
        return ""

    if ttl >= 240:
        return "Network device"
    if ttl >= 120:
        return "Windows"
    if ttl >= 60:
        if "apple" in vendor.lower() and not {22, 445, 139} & ports:
            return "Apple device"
        return "Linux/Unix"
    return ""



def probe_http_identity(ip: str, port: int, timeout: float = 1.5) -> tuple[str, str]:
    """
    Fetch a web endpoint and return ``(server_header, page_title)``.

    Any failure yields empty strings; identity probing must never break a
    scan.

    The whole probe shares one deadline, and ``timeout`` is that deadline
    rather than a per-request allowance. ``IDENTITY_PATHS`` has several
    entries, and charging each one the full timeout turned a single silent
    port into five back-to-back waits -- a device with three web ports cost
    fifteen timeouts, which is what made model identification crawl across a
    sweep. Asking for the remaining slice of the budget instead means the
    probe is bounded by what the caller agreed to wait, however many paths
    it walks. A device that never answers is treated as having said nothing,
    which is the same bargain the banner reader makes.
    """
    scheme = "https" if port in (443, 8443) else "http"
    if scheme == "https":
        import ssl

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handler = urllib.request.HTTPSHandler(context=context)
        opener = urllib.request.build_opener(handler)
    else:
        opener = urllib.request.build_opener()

    deadline = time.monotonic() + timeout
    for path in IDENTITY_PATHS:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        request = urllib.request.Request(
            f"{scheme}://{ip}:{port}{path}",
            headers={"User-Agent": "IP-Inspector/1.0"},
        )
        try:
            with opener.open(request, timeout=remaining) as response:
                server = response.headers.get("Server", "") or ""
                body = response.read(4096).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - any failure just means "no info"
            continue

        match = _TITLE.search(body)
        title = _clean(match.group(1)) if match else ""
        if title or server:
            return _clean(server), title
    return "", ""


def model_from_hostname(hostname: str, vendor: str) -> str:
    """
    Extract a plausible model from a hostname.

    ``printer-hp-laserjet-m404`` with vendor ``HP Inc.`` yields
    ``LaserJet M404``. Returns "" when nothing convincing is found.
    """
    if not hostname:
        return ""
    tokens = [t for t in re.split(r"[^A-Za-z0-9]+", hostname) if len(t) > 1]
    if not tokens:
        return ""

    # Drop vendor words and generic role words; keep what describes the model.
    vendor_tokens = {t.lower() for t in re.split(r"[^A-Za-z0-9]+", vendor) if t}
    remainder = [
        t for t in tokens
        if t.lower() not in vendor_tokens
        and t.lower() not in _GENERIC_TOKENS
        and not t.isdigit()
    ]
    if not remainder:
        return ""

    # Accept only when it looks like a model: several words, or one that
    # mixes letters and digits (HFW2431S, M404, rwxr01).
    looks_like_model = len(remainder) >= 2 or any(
        any(c.isdigit() for c in t) and any(c.isalpha() for c in t)
        for t in remainder
    )
    if not looks_like_model:
        return ""

    return " ".join(remainder[:4])[:50]


def identify_model(ip: str, hostname: str, vendor: str,
                   open_ports: list[int], timeout: float = 1.5) -> str:
    """
    Best-effort model identification for a device.

    Tries HTTP fingerprinting first (most reliable), then falls back to
    hostname heuristics and finally to the vendor family.
    """
    for port in open_ports:
        if port not in IDENTITY_PORTS:
            continue
        server, title = probe_http_identity(ip, port, timeout)
        for candidate in (title, server):
            if candidate:
                return candidate

    from_hostname = model_from_hostname(hostname, vendor)
    if from_hostname:
        return from_hostname

    lowered = vendor.lower()
    for fragment, family in _VENDOR_MODEL_HINTS:
        if fragment in lowered:
            return family
    return ""

# ---------------------------------------------------------------------------
# Camera / NVR identification (ONVIF, UPnP, RTSP)
# ---------------------------------------------------------------------------

#: Endpoints that expose a device description on cameras and NVRs.
DEVICE_DESCRIPTION_PATHS = (
    "/onvif/device_service",   # ONVIF: model, manufacturer, firmware
    "/description.xml",        # UPnP: friendlyName, modelName, manufacturer
    "/rootDesc.xml",
    "/device.xml",
)

#: Substrings that confirm the device really is a camera or NVR.
_CAMERA_MARKERS = ("onvif", "camera", "ipcam", "networkvideocontroller",
                   "nvr", "dvr", "rtsp", "videoencoder", "hikvision",
                   "dahua", "axis", "dahua")


def probe_device_description(ip: str, port: int, timeout: float = 2.0) -> dict:
    """
    Query ONVIF / UPnP device descriptions for a camera identity.

    Returns the fields we could extract; empty dict when the device does
    not answer on any of the known endpoints.
    """
    import urllib.error
    import urllib.request

    base = f"http://{ip}:{port}"
    for path in DEVICE_DESCRIPTION_PATHS:
        try:
            request = urllib.request.Request(
                base + path, headers={"User-Agent": "IP-Inspector/1.0"}
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read(8192).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - any failure means "not this endpoint"
            continue

        lowered = body.lower()
        if not any(marker in lowered for marker in _CAMERA_MARKERS):
            continue

        return {
            "model": _xml_value(body, ("modelname", "model", "friendlyname",
                                        "devicename", "productname")),
            "vendor": _xml_value(body, ("manufacturer", "manufacturername",
                                        "vendor", "maker")),
            "source": "ONVIF/UPnP",
        }
    return {}


def _xml_value(document: str, tags: tuple[str, ...]) -> str:
    """Return the text of the first matching tag in an XML/SSDP document."""
    for tag in tags:
        for open_tag, close in (("<{0}>", "</{0}>"), ("<{0}>", "</{0}>")):
            start = document.lower().find(open_tag.format(tag).lower())
            if start == -1:
                continue
            end = document.lower().find(close.format(tag).lower(), start)
            if end == -1:
                continue
            value = document[start + len(open_tag.format(tag)):
                             end - start - len(open_tag.format(tag))]
            value = " ".join(value.split())
            if value:
                return value[:60]
    return ""


def probe_rtsp_banner(ip: str, port: int = 554, timeout: float = 1.5) -> str:
    """
    Read the RTSP greeting without authenticating.

    Servers answer ``RTSP/1.0 200 OK`` and usually advertise their
    streaming stack in the Server header, which identifies the vendor.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"OPTIONS rtsp://" + ip.encode() + b"/ RTSP/1.0\r\nCSeq: 1\r\n\r\n")
            data = sock.recv(512).decode("utf-8", errors="replace")
    except OSError:
        return ""

    for line in data.splitlines():
        if line.lower().startswith("server:"):
            return _clean(line.split(":", 1)[1])
    return "RTSP" if data.upper().startswith("RTSP") else ""


def identify_camera(ip: str, open_ports: list[int]) -> tuple[str, str]:
    """
    Identify a camera or NVR.

    Returns ``(model, vendor)`` using ONVIF/UPnP first, then the RTSP
    banner, then the web title.
    """
    for port in open_ports:
        if port in (80, 81, 8000, 8080, 443, 37777, 8899, 34567):
            info = probe_device_description(ip, port)
            if info.get("model") or info.get("vendor"):
                return info.get("model", ""), info.get("vendor", "")

    if 554 in open_ports:
        banner = probe_rtsp_banner(ip)
        if banner:
            return banner, ""

    for port in open_ports:
        if port in (80, 8000, 8080, 443):
            _server, title = probe_http_identity(ip, port)
            if title:
                return title, ""
    return "", ""