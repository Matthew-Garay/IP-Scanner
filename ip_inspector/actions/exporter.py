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
        "alive": device.is_alive,
        "vpn": device.is_vpn_active,
        "ttl": device.ttl,
        "tcp_window": device.tcp_window,
        "latency_ms": device.response_time_ms,
        "discovery": device.discovery_method,
        "risk_score": device.risk_score,
        "inventory_state": device.inventory_state,
        "first_seen": device.first_seen,
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
    Write the full inventory as JSON and return the path written.

    ``extra`` carries the session context (scanned range, inventory changes),
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
