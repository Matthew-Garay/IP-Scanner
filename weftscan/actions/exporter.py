"""Write the discovered hosts to CSV or JSON.

Two audiences, one code path. CSV is for people: a flat table that opens in
Excel and can be attached to a report. JSON is for the next tool: the same
devices with every field, the open ports and the findings, plus whatever
session context the caller wants to attach.

The CSV is written UTF-8 with a BOM and separated by semicolons. Excel on
Windows otherwise assumes the local code page and renders every vendor name
with an accent as two broken characters.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence

from ..core.models import Device

#: Column order, matching :meth:`Device.to_row`. Kept in English so the file
#: reads the same whatever language the operator was working in.
CSV_HEADERS: tuple[str, ...] = (
    "IP", "Status", "Hostname", "MAC", "Vendor", "Model", "OS", "Type", "VPN",
    "TTL", "Latency (ms)", "Discovery", "Open ports",
)


def _target(path: str | Path, suffix: str) -> Path:
    """Resolve the destination, forcing the extension and creating the folder."""
    target = Path(path)
    if target.suffix.lower() != suffix:
        target = target.with_suffix(suffix)
    target.parent.mkdir(parents=True, exist_ok=True)
    return target


def export_csv(devices: Iterable[Device], path: str | Path) -> Path:
    """Write one row per device and return the path written."""
    target = _target(path, ".csv")
    with target.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle, delimiter=";")
        writer.writerow(CSV_HEADERS)
        for device in devices:
            writer.writerow(device.to_row())
    return target


def device_to_dict(device: Device) -> dict:
    """Everything known about one device, in a JSON friendly shape."""
    return {
        "ip": device.ip_address,
        "mac": device.mac_address,
        "hostname": device.hostname,
        "vendor": device.vendor,
        "model": device.model,
        "os": device.os_name,
        "type": device.device_type,
        "category": device.category,
        "details": dict(device.details),
        "alive": device.is_alive,
        "vpn": device.is_vpn_active,
        "ttl": device.ttl,
        "tcp_window": device.tcp_window,
        "latency_ms": device.response_time_ms,
        "discovery": device.discovery_method,
        "risk_score": device.risk_score,
        "ports": [
            {
                "number": port.number,
                "state": port.state,
                "service": port.service,
                "version": port.version,
                "banner": port.banner,
                "latency_ms": port.latency_ms,
            }
            for port in device.open_ports
        ],
        "findings": [
            {
                "severity": finding.severity,
                "title": finding.title,
                "detail": finding.detail,
                "target": finding.target,
            }
            for finding in device.findings
        ],
    }


def export_json(
    devices: Iterable[Device], path: str | Path, extra: dict | None = None
) -> Path:
    """
    Write every device as JSON and return the path written.

    ``extra`` carries the session context (scanned range, VPN posture),
    so the file documents how the data was obtained and not only what it found.
    """
    target = _target(path, ".json")
    listed: Sequence[Device] = list(devices)
    payload: dict = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "device_count": len(listed),
        "devices": [device_to_dict(device) for device in listed],
    }
    if extra:
        payload["session"] = extra
    target.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return target


def export(devices: Iterable[Device], path: str | Path, extra: dict | None = None) -> Path:
    """
    Export in the format the extension asks for: ``.csv`` or ``.json``.

    Anything else is written as JSON, which is the lossless of the two.
    """
    target = Path(path)
    if target.suffix.lower() == ".csv":
        return export_csv(devices, target)
    return export_json(devices, target, extra)


def device_from_dict(data: dict) -> Device:
    """Rebuild a Device from :func:`device_to_dict` output (inverse function)."""
    from ..core.models import Port, SecurityFinding

    device = Device(
        ip_address=str(data["ip"]),
        mac_address=data.get("mac"),
        hostname=data.get("hostname") or "",
        vendor=data.get("vendor") or "",
        model=data.get("model") or "",
        os_name=data.get("os") or "",
        device_type=data.get("type") or "Unknown",
        is_alive=bool(data.get("alive", True)),
        is_vpn_active=bool(data.get("vpn", False)),
        ttl=data.get("ttl"),
        tcp_window=data.get("tcp_window"),
        response_time_ms=data.get("latency_ms"),
        discovery_method=data.get("discovery") or "",
        risk_score=int(data.get("risk_score") or 0),
        category=data.get("category") or "",
        details={str(k): str(v) for k, v in (data.get("details") or {}).items()},
    )
    device.open_ports = [
        Port(int(p["number"]), p.get("state", "open"), p.get("service") or "",
             banner=p.get("banner") or "", version=p.get("version") or "",
             latency_ms=p.get("latency_ms"))
        for p in data.get("ports", [])
    ]
    device.findings = [
        SecurityFinding(f.get("severity", "info"), f.get("title", ""),
                        f.get("detail", ""), f.get("target", ""))
        for f in data.get("findings", [])
    ]
    return device


def load_json(path: str | Path) -> tuple[list[Device], dict]:
    """
    Read a file written by :func:`export_json`.

    Returns the devices and the session block (range, profile…). Raises
    ``ValueError`` with a readable message when the file is not an export.
    """
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"Cannot read {path}: {exc}") from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"{Path(path).name} is not valid JSON ({exc.msg}, line {exc.lineno})") \
            from None
    if not isinstance(payload, dict) or not isinstance(payload.get("devices"), list):
        raise ValueError(f"{Path(path).name} is not a WeftScan results file")
    try:
        devices = [device_from_dict(item) for item in payload["devices"]]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"{Path(path).name} has an invalid device entry: {exc}") from None
    session = payload.get("session") if isinstance(payload.get("session"), dict) else {}
    session.setdefault("generated", payload.get("generated", ""))
    return devices, session
