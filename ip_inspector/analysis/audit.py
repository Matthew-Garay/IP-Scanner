"""Security auditing: TLS inspection, HTTP posture and device risk scoring.

Audits are deliberately conservative: they report observable facts about a
target (expired certificates, missing headers, risky exposed services)
without attempting exploitation.
"""

from __future__ import annotations

import socket
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from ..core.models import Device, HttpReport, SecurityFinding, TlsReport

#: HTTP headers that harden a site when present: (header, severity, meaning).
SECURITY_HEADERS: tuple[tuple[str, str, str], ...] = (
    ("Strict-Transport-Security", "high", "Ausencia de HSTS: no se fuerza HTTPS"),
    ("Content-Security-Policy", "medium", "Sin CSP: riesgo de XSS"),
    ("X-Frame-Options", "medium", "Sin X-Frame-Options: vulnerable a clickjacking"),
    ("X-Content-Type-Options", "low", "Sin X-Content-Type-Options: permite MIME sniffing"),
    ("Referrer-Policy", "low", "Sin Referrer-Policy: filtra URLs a terceros"),
    ("Permissions-Policy", "info", "Sin Permissions-Policy: no restringe APIs"),
)

#: TLS versions considered obsolete.
WEAK_PROTOCOLS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})

#: Exposed ports that carry a clear risk: (severity, explanation).
RISKY_PORTS: dict[int, tuple[str, str]] = {
    21: ("medium", "FTP sin cifrar: credenciales en texto claro"),
    23: ("high", "Telnet expuesto: control remoto sin cifrar"),
    69: ("medium", "TFTP sin autenticacion"),
    445: ("high", "SMB expuesto: superficie de EternalBlue"),
    512: ("medium", "rexec activo"),
    513: ("medium", "rlogin activo"),
    514: ("low", "Syslog expuesto"),
    873: ("high", "rsync sin cifrar"),
    1080: ("low", "SOCKS proxy: util para pivotar"),
    2049: ("high", "NFS expuesto: acceso al sistema de ficheros"),
    3306: ("high", "MySQL accesible desde la red"),
    3389: ("medium", "RDP expuesto: objetivo de fuerza bruta"),
    5432: ("high", "PostgreSQL accesible desde la red"),
    5900: ("medium", "VNC: suele usar contrasenas cortas"),
    6379: ("critical", "Redis sin TLS: RCE en versiones antiguas"),
    9200: ("high", "Elasticsearch sin autenticacion"),
    11211: ("medium", "Memcached sin autenticacion"),
    27017: ("high", "MongoDB accesible desde la red"),
}

#: Severity weights used to fold findings into a single risk score.
_SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 30, "high": 15, "medium": 7, "low": 3, "info": 0,
}


# ---------------------------------------------------------------------------
# TLS inspection
# ---------------------------------------------------------------------------

def inspect_tls(host: str, port: int = 443, timeout: float = 5.0) -> TlsReport:
    """Connect over TLS and report protocol, cipher and certificate chain."""
    report = TlsReport(host=host, port=port)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                report.supported = True
                report.protocol = tls.version() or ""
                cipher = tls.cipher()
                report.cipher = cipher[0] if cipher else ""

                certificate = tls.getpeercert() or _decode_certificate(tls.getpeercert(True))
                report.subject = _format_name(certificate.get("subject", ()))
                report.issuer = _format_name(certificate.get("issuer", ()))
                report.not_before = certificate.get("notBefore", "")
                report.not_after = certificate.get("notAfter", "")
                report.days_remaining = _days_until(report.not_after)
                report.subject_alt_names = [
                    value for kind, value in certificate.get("subjectAltName", ())
                    if kind == "DNS"
                ]
                report.findings = _tls_findings(report)
    except (OSError, ssl.SSLError, ValueError) as exc:
        report.error = str(exc)
    return report


def _decode_certificate(der: bytes) -> dict:
    """
    Decode DER certificate bytes into the mapping shape of ``getpeercert``.

    With ``CERT_NONE`` verification disabled, ``getpeercert()`` returns an
    empty mapping, so we re-read the raw DER. The standard library decoder
    only accepts a file path, hence the short-lived temporary PEM file.
    """
    import tempfile

    try:
        from ssl import _ssl

        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile(
            "w", suffix=".pem", delete=False, encoding="utf-8"
        ) as handle:
            handle.write(pem)
            pem_path = handle.name
        try:
            return dict(_ssl._test_decode_cert(pem_path))  # type: ignore[attr-defined]
        finally:
            import os

            try:
                os.unlink(pem_path)
            except OSError:
                pass
    except Exception:  # noqa: BLE001 - internal API: degrade to "no details"
        return {}


def _format_name(entries: tuple) -> str:
    """Flatten an X.509 Name tuple into a readable, comma-separated string."""
    parts: list[str] = []
    for relative_name in entries or ():
        for attribute in relative_name:
            value = attribute[-1]
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")
            parts.append(str(value))
    return ", ".join(parts)


def _days_until(not_after: str) -> int | None:
    """Days until a certificate expires, or None when the date is unreadable."""
    if not not_after:
        return None
    for date_format in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            expiry = datetime.strptime(not_after, date_format).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        return (expiry - datetime.now(timezone.utc)).days
    return None


def _tls_findings(report: TlsReport) -> list[str]:
    """Turn certificate facts into human-readable observations."""
    findings: list[str] = []
    if report.protocol in WEAK_PROTOCOLS:
        findings.append(f"Protocolo obsoleto: {report.protocol}")
    if report.days_remaining is not None:
        if report.days_remaining < 0:
            findings.append(f"Certificado EXPIRADO hace {-report.days_remaining} dias")
        elif report.days_remaining < 15:
            findings.append(f"Certificado caduca en {report.days_remaining} dias")
    if report.issuer:
        findings.append(f"Emitido por: {report.issuer}")
    if report.supported and not report.subject_alt_names:
        findings.append("Sin subjectAltName (SNI)")
    return findings


# ---------------------------------------------------------------------------
# HTTP posture
# ---------------------------------------------------------------------------

def audit_http(url: str, timeout: float = 6.0) -> HttpReport:
    """Fetch an HTTP(S) endpoint and score its security headers."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    report = HttpReport(url=url)
    started = time.perf_counter()

    request = urllib.request.Request(
        url, method="GET", headers={"User-Agent": "IP-Inspector/1.0"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            report.status_code = response.status
            report.headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        report.status_code = exc.code
        report.headers = dict((exc.headers or {}).items())
    except (urllib.error.URLError, OSError, ValueError) as exc:
        report.error = str(exc)

    report.elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
    report.server = report.headers.get("Server", "")
    report.findings = _http_findings(report)
    return report


def _http_findings(report: HttpReport) -> list[tuple[str, str]]:
    """Check the response for missing or misconfigured security headers."""
    if report.status_code is None:
        return []

    present = {key.lower() for key in report.headers}
    findings = [
        (severity, description)
        for header, severity, description in SECURITY_HEADERS
        if header.lower() not in present
    ]

    cookies = report.headers.get("Set-Cookie", "")
    if cookies:
        if "secure" not in cookies.lower():
            findings.append(("medium", "Cookie sin el atributo Secure"))
        if "httponly" not in cookies.lower():
            findings.append(("low", "Cookie sin el atributo HttpOnly"))

    return findings


# ---------------------------------------------------------------------------
# Device risk
# ---------------------------------------------------------------------------

def audit_device(device: Device) -> list[SecurityFinding]:
    """
    Generate security findings for one discovered device.

    The offline heuristics run first because they cost nothing; the network
    probes that follow are the expensive part and only cover what the
    heuristics did not, namely the certificate and the vendor prefix.
    """
    from .exposure import exposure_findings

    findings: list[SecurityFinding] = exposure_findings(device)

    if device.mac_address and not device.vendor:
        findings.append(
            SecurityFinding(
                "info", "MAC sin fabricante",
                "Prefijo OUI no registrado (posiblemente aleatorizada)", device.ip_address,
            )
        )

    for port in device.open_ports:
        if port.is_open and port.number in (443, 8443):
            tls = inspect_tls(device.ip_address, port.number)
            for issue in tls.findings:
                severity = "high" if "EXPIRADO" in issue or "obsoleto" in issue else "info"
                findings.append(
                    SecurityFinding(severity, f"TLS/{port.number}", issue, device.ip_address)
                )

    return sorted(findings, key=lambda item: item.sort_weight)


def risk_score(findings: list[SecurityFinding]) -> int:
    """Fold findings into a 0-100 risk score, where higher means worse."""
    return min(100, sum(_SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings))