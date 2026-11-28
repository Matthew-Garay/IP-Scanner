"""
Write ``docs/sample-results.json``: a fictional small-office network.

The sample lets anyone try the interface (File > Open results) without
scanning, and is what the README screenshots show, so no real network's
addresses, names or MAC addresses end up in the repository.

    python tools/make_sample.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from weftscan.actions.exporter import export_json  # noqa: E402
from weftscan.analysis.exposure import exposure_findings, exposure_score  # noqa: E402
from weftscan.core.models import KNOWN_SERVICES, Device, Port  # noqa: E402

NET = "192.168.50"

#: ip suffix, name, category, engine type, vendor, model, OS, MAC, ports, details
DEVICES = (
    (1, "", "router", "Router", "TP-Link", "Archer AX55", "Linux/Unix", "50:91:E3:4A:10:01",
     (53, 80, 443), {"Role": "Default gateway",
                     "UPnP device": "InternetGatewayDevice, WANDevice"}),
    (10, "FRONT-DESK-PC", "computer", "Windows PC", "Dell Inc.", "OptiPlex 7010", "Windows",
     "B0:7B:25:3C:21:0A", (135, 139, 445, 3389), {}),
    (11, "ACCOUNTING-LT", "laptop", "Windows PC", "Lenovo", "ThinkPad T14", "Windows",
     "8C:16:45:7E:02:11", (135, 445), {}),
    (12, "design-mac", "computer", "Apple Device", "Apple, Inc.", "iMac 24", "macOS",
     "F0:18:98:6D:33:12", (22, 445, 5900), {"Announced services": "File sharing (SMB), SSH"}),
    (20, "nas-01", "storage", "Linux Server", "Synology Incorporated", "DiskStation DS920+",
     "Linux/Unix", "00:11:32:9A:4C:20", (22, 80, 443, 445, 5000, 5001),
     {"UPnP device": "Basic"}),
    (30, "Office printer", "printer", "Printer", "HP Inc.", "LaserJet Pro M404dn", "",
     "9C:7B:EF:12:55:30", (80, 443, 631, 9100),
     {"Announced services": "IPP printing, Raw printing, eSCL scanning"}),
    (40, "Lobby camera", "camera", "IP Camera", "Hikvision", "DS-2CD2143G2-I", "Linux/Unix",
     "44:19:B6:20:8F:40", (80, 554, 8000), {}),
    (50, "Meeting room TV", "tv", "Unknown", "LG Electronics", "OLED55C1", "",
     "A8:23:FE:51:0C:50", (1900, 3000), {"UPnP device": "MediaRenderer, dial"}),
    (51, "Reception speaker", "speaker", "Unknown", "Sonos, Inc.", "Sonos One", "",
     "5C:AA:FD:61:7B:51", (1400,), {"Announced services": "AirPlay audio, Sonos"}),
    (60, "Ana's iPhone", "phone", "Unknown", "Apple, Inc.", "iPhone 15", "",
     "3C:22:FB:0E:71:60", (), {"Announced services": "Apple device"}),
    (61, "", "phone", "Unknown", "", "", "Linux/Unix", "DA:4F:11:92:3E:61", (),
     {"MAC address type": "Randomized (private address)"}),
    (70, "Kiosk-iPad", "tablet", "Unknown", "Apple, Inc.", "iPad (10th gen)", "",
     "28:6A:BA:44:19:70", (), {}),
    (80, "Hue Bridge", "smart_home", "IoT Device", "Signify Netherlands", "BSB002", "",
     "EC:B5:FA:2D:6E:80", (80, 443), {"Announced services": "HomeKit accessory"}),
    (90, "Lobby display", "media", "Unknown", "Google, Inc.", "Chromecast", "",
     "F4:F5:D8:0B:52:90", (8008, 8009), {"Announced services": "Chromecast / Google Cast"}),
    (100, "build-server", "server", "Linux Server", "Super Micro Computer", "", "Linux/Unix",
     "AC:1F:6B:7C:3A:64", (22, 80, 3306, 6379), {}),
    (120, "Break room PS5", "console", "Unknown", "Sony Interactive Entertainment", "PS5", "",
     "00:D9:D1:5E:14:78", (), {}),
    (200, "ap-floor-2", "access_point", "Network Device", "Ubiquiti Inc", "U6-Lite",
     "Linux/Unix", "74:83:C2:31:9B:C8", (22,), {"UPnP device": "WLANAccessPointDevice"}),
)


def build() -> list[Device]:
    devices = []
    for index, (suffix, name, category, kind, vendor, model, os_name, mac, ports,
                details) in enumerate(DEVICES):
        device = Device(
            ip_address=f"{NET}.{suffix}", mac_address=mac, hostname=name, vendor=vendor,
            model=model, device_type=kind, os_name=os_name, category=category,
            discovery_method="ARP", response_time_ms=1.0 + (index * 7) % 23,
            ttl=128 if os_name == "Windows" else 64,
            details=dict(details),
            open_ports=[Port(port, "open", KNOWN_SERVICES.get(port, "")) for port in ports],
        )
        device.findings = exposure_findings(device)
        device.risk_score = exposure_score(device)
        devices.append(device)
    return devices


def main() -> None:
    target = ROOT / "docs" / "sample-results.json"
    export_json(build(), target, {"range": f"{NET}.0/24", "profile": "standard",
                                  "note": "Fictional sample network for demos and screenshots"})
    print(f"Wrote {target}")


if __name__ == "__main__":
    main()
