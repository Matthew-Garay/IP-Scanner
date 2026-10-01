"""ICMP probes: TTL, round-trip time, and the shell plumbing they need.

Split out of the tools tab because the scanning engine needs the TTL too.
``network`` fingerprints the operating system from it, and an engine that
imported from the tools tab would be reaching sideways into the interface
layer to do so.

This module must never import the user interface. It shells out to the
system ping binary, which is the only way to read a TTL without raw
sockets: scapy needs elevation, the system ping does not.
"""

from __future__ import annotations

import re
import subprocess
import sys

#: Hide console windows spawned by subprocess on Windows.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def console_encoding() -> str:
    """
    Encoding used by the command line tools this module shells out to.

    Windows writes them in the OEM code page -- 850 for a Spanish console --
    not in UTF-8, so decoding as UTF-8 turns "Estadisticas" with a tilde into
    replacement characters in every tool. Asking the kernel keeps the
    catalogue correct on any locale without guessing from a language.
    """
    if sys.platform != "win32":
        return "utf-8"
    try:
        import ctypes

        return f"cp{ctypes.windll.kernel32.GetOEMCP()}"
    except Exception:  # noqa: BLE001 - fall back to the ANSI code page
        return "mbcs"


def run_command(command: list[str], timeout: float = 20.0) -> tuple[int, str, str]:
    """Run an external tool, returning ``(code, stdout, stderr)``."""
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding=console_encoding(),
            errors="replace",
            creationflags=_NO_WINDOW,
        )
        return completed.returncode, completed.stdout, completed.stderr
    except FileNotFoundError:
        return 127, "", f"{command[0]} no esta instalado en el sistema"
    except subprocess.TimeoutExpired:
        return 124, "", f"{command[0]} supero {timeout:.0f}s"
    except OSError as exc:
        return 1, "", str(exc)


def _ping_command(host: str, timeout: float) -> list[str]:
    """One echo request, in the syntax of the host operating system."""
    if sys.platform == "win32":
        return ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    return ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host]


#: Round-trip time as printed by ping, in English or Spanish Windows.
#: The unit is matched as a bare ``m`` because Spanish Windows really does
#: print ``tiempo<1m`` (no trailing s) for a sub-millisecond answer.
_PING_RTT = re.compile(
    r"(?:time|tiempo)\s*(?P<sep>[<=])\s*(?P<value>\d+(?:\.\d+)?)\s*m", re.IGNORECASE
)


def parse_ping_rtt(output: str) -> float | None:
    """
    Round-trip time of a ping reply in milliseconds, or ``None`` on loss.

    Windows answers a sub-millisecond round trip as ``time<1ms``; it is
    reported as zero, which is what the caller would have seen.
    """
    match = _PING_RTT.search(output)
    if not match:
        return None
    return 0.0 if match.group("sep") == "<" else float(match.group("value"))


#: The observed TTL as printed by ping: ``TTL=128`` on Windows, ``ttl 64`` on
#: Linux, in either language.
_PING_TTL = re.compile(r"ttl[=\s]+(\d+)", re.IGNORECASE)


def parse_ping_ttl(output: str) -> int | None:
    """The initial TTL a ping reply reports, or ``None`` when it is absent.

    This is the only way to read the TTL without raw sockets: scapy needs
    elevation, while the system ping binary does not. It is what makes the
    operating system fingerprint work for an unelevated scan.
    """
    match = _PING_TTL.search(output)
    return int(match.group(1)) if match else None


def ping_ttl(host: str, timeout: float = 1.0) -> int | None:
    """Send one echo request and return the TTL it came back with."""
    target = host.strip()
    if not target:
        return None
    _code, stdout, _stderr = run_command(_ping_command(target, timeout), timeout + 3.0)
    return parse_ping_ttl(stdout)


def ping_once(host: str, timeout: float = 1.5) -> float | None:
    """
    Send a single echo request and return its round-trip time.

    One packet per call is what lets the live graph follow the cadence the
    operator chose instead of a tool's fixed batch of twenty. A lost packet
    comes back as ``None``, which the sparkline draws as a gap in the line.
    """
    target = host.strip()
    if not target:
        return None
    _code, stdout, _stderr = run_command(_ping_command(target, timeout), timeout + 3.0)
    return parse_ping_rtt(stdout)
