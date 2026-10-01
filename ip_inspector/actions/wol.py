"""Wake-on-LAN magic packet."""

from __future__ import annotations

import socket

from ..core.models import normalize_mac_address


def magic_packet(mac: str) -> bytes:
    """Build the 102-byte WoL packet for a MAC address."""
    normalized = normalize_mac_address(mac)
    if not normalized:
        raise ValueError(f"Invalid MAC: {mac!r}")
    return b"\xff" * 6 + bytes.fromhex(normalized.replace(":", "")) * 16


def send_wol(mac: str, broadcast: str | None = None, port: int = 9) -> int:
    """Send the magic packet; returns how many destinations were tried."""
    packet = magic_packet(mac)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.sendto(packet, (broadcast or "255.255.255.255", port))
            return 1
        except OSError:
            return 0