"""Device actions launched from the results table context menu."""

from __future__ import annotations

import subprocess
import sys
import webbrowser

#: Ports where opening a browser makes sense.
WEB_PORTS = (80, 443, 8000, 8080, 8443, 5000)

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def best_web_port(device) -> int | None:
    """First open web port of a device, or None when there is none."""
    for port in WEB_PORTS:
        if device.has_port(port):
            return port
    return None


def open_remote_desktop(ip: str) -> tuple[bool, str]:
    """
    Launch the Remote Desktop client against a host.

    Returns ``(ok, message)`` so the UI can surface the failure.
    """
    if sys.platform != "win32":
        return False, "Remote Desktop (mstsc) is only available on Windows"
    try:
        subprocess.Popen(["mstsc", f"/v:{ip}"], creationflags=_NO_WINDOW)
    except OSError:
        return False, "Could not start mstsc.exe"
    return True, ip


def open_web(ip: str, port: int) -> bool:
    """Open an http(s) URL in the default browser."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}" + ("" if port in (80, 443) else f":{port}")
    try:
        return webbrowser.open(url)
    except webbrowser.Error:
        return False


def wake_device(device) -> tuple[bool, str]:
    """
    Send the Wake-on-LAN magic packet to a device.

    Returns ``(ok, reason)``: a magic packet is UDP, so a success only means
    the datagram left this machine. The reason is still worth surfacing, since
    the usual failure is a broadcast the local policy refuses to route.
    """
    if not device.mac_address:
        return False, "This device has no MAC address on record"
    from .wol import send_wol

    try:
        sent = send_wol(device.mac_address)
    except ValueError:
        return False, f"{device.mac_address} is not a valid MAC address"
    except OSError as exc:
        return False, str(exc)
    if sent < 1:
        return False, "The broadcast could not be sent from this adapter"
    return True, device.mac_address