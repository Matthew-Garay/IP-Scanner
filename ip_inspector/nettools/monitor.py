"""Continuous uptime monitoring with transition alerts.

A fixed host (server, NVR, gateway) can be pinned here and polled on an
interval. Only *state transitions* raise an alert: going down and coming
back. A host that stays down does not repeat the same warning every few
seconds, which is what makes a difference between a monitor you keep
open and one you mute.

Probing prefers ICMP when the process is elevated and falls back to a
TCP connect otherwise, because Windows blocks raw ICMP for standard
users. Either way the measurement is a real round trip.
"""

from __future__ import annotations

import asyncio
import importlib
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime

from ..core.utils import is_elevated

#: Ports tried, in order, when a watched host has no explicit port.
FALLBACK_PORTS: tuple[int, ...] = (80, 443, 445, 22, 3389, 8080)

#: Rolling window kept for the latency sparkline.
HISTORY_SIZE = 60

#: Serialises ICMP probes. Raw sockets and the scapy import are not
#: thread-safe, so only one host may use ICMP at a time; everyone else
#: falls back to TCP. Flipped off for good if a probe ever blows up.
_icmp_lock: asyncio.Lock | None = None
_icmp_ready: bool | None = None


def _warm_icmp() -> bool:
    """Import scapy once, in a worker thread, and cache the verdict."""
    global _icmp_ready
    if _icmp_ready is None:
        try:
            importlib.import_module("scapy.all")
            _icmp_ready = is_elevated()
        except Exception:  # noqa: BLE001
            _icmp_ready = False
    return _icmp_ready

STATUS_UP = "up"
STATUS_DOWN = "down"
STATUS_UNKNOWN = "unknown"


async def _probe_tcp(ip: str, port: int, timeout: float) -> float | None:
    """Round-trip time of a TCP connect, or None when it fails."""
    loop = asyncio.get_running_loop()
    started = loop.time()
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError, ConnectionError):
        return None
    try:
        writer.close()
        await writer.wait_closed()
    except (OSError, ConnectionResetError):
        pass
    return round((loop.time() - started) * 1000, 2)


def _probe_icmp(ip: str, timeout: float) -> float | None:
    """ICMP round trip through scapy; returns None without privileges."""
    if not is_elevated():
        return None
    started = time.perf_counter()
    try:
        from scapy.all import ICMP, IP, sr1

        if sr1(IP(dst=ip) / ICMP(), timeout=timeout, verbose=0) is None:
            return None
    except Exception:  # noqa: BLE001 - raw socket refused
        return None
    return round((time.perf_counter() - started) * 1000, 2)


async def _icmp_probe(ip: str, timeout: float) -> float | None:
    """ICMP round trip, serialised and fail-safe."""
    global _icmp_ready
    async with _icmp_lock:
        try:
            loop = asyncio.get_running_loop()
            warmed = await loop.run_in_executor(None, _warm_icmp)
            if not warmed:
                return None
            return await loop.run_in_executor(None, _probe_icmp, ip, timeout)
        except Exception:  # noqa: BLE001 - never let ICMP break monitoring
            _icmp_ready = False
            return None


async def probe(ip: str, port: int, timeout: float,
                known: int = 0, first: bool = True) -> tuple[float | None, int]:
    """
    Measure a host and report which port answered.

    Tries the port that worked last time first, so a pinned host settles
    on a single fast probe instead of walking the whole list every round.
    When nothing is known yet the candidate ports are tried concurrently:
    a serial walk would cost len(FALLBACK_PORTS) x timeout per dead host.

    Returns ``(latency_ms, port)``; port 0 means nothing answered.
    """
    if port > 0:
        latency = await _probe_tcp(ip, port, timeout)
        return latency, port
    if known > 0:
        latency = await _probe_tcp(ip, known, timeout)
        if latency is not None:
            return latency, known

    # ICMP costs an import and a raw socket, so it is attempted once per
    # host, under a lock, and never on the hot path: after that the cached
    # TCP port answers in a single round trip.
    if first and _icmp_lock is not None:
        icmp = await _icmp_probe(ip, timeout)
        if icmp is not None:
            return icmp, 0

    results = await asyncio.gather(
        *(_probe_tcp(ip, candidate, timeout) for candidate in FALLBACK_PORTS),
        return_exceptions=True,
    )
    for candidate, latency in zip(FALLBACK_PORTS, results):
        if isinstance(latency, float):
            return latency, candidate
    return None, 0


@dataclass
class WatchedHost:
    """A pinned host plus its running uptime statistics."""

    ip: str
    label: str = ""
    port: int = 0
    interval: float = 3.0
    timeout: float = 1.5
    #: Consecutive failures before the host is declared down.
    threshold: int = 3

    status: str = STATUS_UNKNOWN
    checks: int = 0
    losses: int = 0
    failures: int = 0
    streak_ok: int = 0
    last_latency: float | None = None
    min_latency: float | None = None
    max_latency: float | None = None
    #: Port that answered last time; reused to keep probes fast.
    known_port: int = 0
    last_change: str = ""
    started: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))
    history: deque = field(default_factory=lambda: deque(maxlen=HISTORY_SIZE))

    @property
    def uptime(self) -> float:
        """Percentage of successful probes."""
        if not self.checks:
            return 100.0
        return round((self.checks - self.losses) * 100 / self.checks, 1)

    @property
    def avg_latency(self) -> float | None:
        """Mean latency over the successful probes."""
        samples = [v for v in self.history if v is not None]
        return round(sum(samples) / len(samples), 1) if samples else None

    @property
    def display(self) -> str:
        return self.label or self.ip

    def snapshot(self) -> dict:
        """Serialisable copy for the UI."""
        return {
            "ip": self.ip, "label": self.label, "port": self.port,
            "status": self.status, "latency": self.last_latency,
            "avg": self.avg_latency, "uptime": self.uptime,
            "losses": self.losses, "checks": self.checks,
            "last_change": self.last_change, "since": self.started,
            "history": list(self.history),
        }


@dataclass
class MonitorEvent:
    """A state transition worth telling the operator about."""

    kind: str            # up | down | recovered | added | removed | info
    ip: str
    label: str
    message: str
    severity: str = "info"   # info | ok | warn | alert
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))


class Monitor:
    """
    Polls a set of pinned hosts and publishes transition alerts.

    One background task per host, all on a private event loop, so a host
    that stops answering never blocks the others. Results travel to the
    UI through a queue; the monitor never touches widgets.
    """

    def __init__(self, event_queue) -> None:
        self._queue = event_queue
        self._hosts: dict[str, WatchedHost] = {}
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._wake: asyncio.Event | None = None

    # -- membership ------------------------------------------------------
    def add(self, ip: str, label: str = "", port: int = 0,
            interval: float = 3.0, timeout: float = 1.5,
            threshold: int = 3) -> WatchedHost | None:
        """Pin a host. Returns the record, or None when it is invalid."""
        ip = str(ip or "").strip()
        if not ip:
            return None
        with self._lock:
            if ip in self._hosts:
                return self._hosts[ip]
            host = WatchedHost(
                ip=ip, label=label or ip, port=port, interval=interval,
                timeout=timeout, threshold=max(1, threshold),
            )
            self._hosts[ip] = host

        self._emit(MonitorEvent(
            "added", ip, host.display,
            f"{host.display} added to monitoring "
            f"(every {interval:g}s, timeout {timeout:g}s)",
        ))
        if self._thread and not self._stop_event.is_set():
            self._loop_soon(self._poll_forever(host))
        return host

    def remove(self, ip: str) -> None:
        """Unpin a host."""
        with self._lock:
            host = self._hosts.pop(ip, None)
        if host is not None:
            self._emit(MonitorEvent(
                "removed", ip, host.display, f"{host.display} removed from monitoring",
                "warn",
            ))

    def clear(self) -> None:
        with self._lock:
            hosts = list(self._hosts)
            self._hosts.clear()
        for host in hosts:
            self._emit(MonitorEvent(
                "removed", host.ip, host.display, f"{host.display} removed", "warn"))

    def snapshot(self) -> list[dict]:
        """Current state of every pinned host, safe to read from the UI."""
        with self._lock:
            return [h.snapshot() for h in self._hosts.values()]

    def __len__(self) -> int:
        with self._lock:
            return len(self._hosts)

    @property
    def running(self) -> bool:
        return self._thread is not None and not self._stop_event.is_set()

    # -- lifecycle -------------------------------------------------------
    def start(self) -> None:
        """Begin polling. Safe to call twice."""
        if self.running or not len(self):
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="monitor"
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop polling and release the event loop."""
        self._stop_event.set()
        loop = self._loop
        wake = getattr(self, "_wake", None)
        if loop is not None:
            def _shutdown() -> None:
                # Wake every sleeper so the tasks return, then park the
                # loop; run_until_complete() raises RuntimeError on stop().
                if wake is not None:
                    wake.set()
                loop.stop()

            try:
                loop.call_soon_threadsafe(_shutdown)
            except RuntimeError:
                pass
        self._thread = None
        self._loop = None
        self._wake = None

    def _run(self) -> None:
        global _icmp_lock, _icmp_ready
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        _icmp_lock = asyncio.Lock()
        _icmp_ready = None
        # Loop-aware stop flag. A threading.Event.wait() would block the
        # whole loop and stall every other host for the interval.
        self._wake = asyncio.Event()
        try:
            with self._lock:
                hosts = list(self._hosts.values())
            tasks = [loop.create_task(self._poll_forever(host)) for host in hosts]
            loop.run_until_complete(asyncio.gather(*tasks))
        except (RuntimeError, asyncio.CancelledError):
            pass
        finally:
            for task in asyncio.all_tasks(loop):
                task.cancel()
            try:
                loop.close()
            except Exception:  # noqa: BLE001
                pass

    def _loop_soon(self, coro) -> None:
        loop = self._loop
        if loop is not None:
            try:
                loop.call_soon_threadsafe(loop.create_task, coro)
            except RuntimeError:
                pass

    # -- polling ---------------------------------------------------------
    async def _poll_forever(self, host: WatchedHost) -> None:
        """Probe a host forever, respecting its interval and stop flag."""
        while not self._stop_event.is_set():
            await self._poll_once(host)
            # Sleep on the async event, not the threading one, so the
            # interval never blocks sibling hosts.
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=host.interval)
                return
            except asyncio.TimeoutError:
                continue

    async def _poll_once(self, host: WatchedHost) -> None:
        first = not host.known_port and host.checks == 0
        latency, port = await probe(
            host.ip, host.port, host.timeout, host.known_port, first
        )
        if port:
            host.known_port = port
        self._record(host, latency)

    def _record(self, host: WatchedHost, latency: float | None) -> None:
        """Update statistics and raise an alert on a status transition."""
        host.checks += 1
        host.history.append(latency)
        previous = host.status

        if latency is None:
            host.losses += 1
            host.failures += 1
            host.streak_ok = 0
            host.last_latency = None
            # Stay "unknown" during the grace period before declaring down.
            if host.failures >= host.threshold:
                host.status = STATUS_DOWN
        else:
            host.failures = 0
            host.streak_ok += 1
            host.last_latency = latency
            host.min_latency = (
                latency if host.min_latency is None
                else min(host.min_latency, latency)
            )
            host.max_latency = (
                latency if host.max_latency is None
                else max(host.max_latency, latency)
            )
            if host.status != STATUS_UP:
                host.status = STATUS_UP

        if host.status == previous:
            return

        host.last_change = datetime.now().strftime("%H:%M:%S")
        if host.status == STATUS_DOWN:
            self._emit(MonitorEvent(
                "down", host.ip, host.display,
                f"{host.display} stopped responding "
                f"({host.failures} consecutive failures)",
                "alert",
            ))
        elif previous == STATUS_DOWN:
            self._emit(MonitorEvent(
                "recovered", host.ip, host.display,
                f"{host.display} is back online "
                f"({host.last_latency:.0f} ms)",
                "ok",
            ))
        else:
            self._emit(MonitorEvent(
                "up", host.ip, host.display,
                f"{host.display} answered ({host.last_latency:.0f} ms)",
                "ok",
            ))

    def _emit(self, event: MonitorEvent) -> None:
        self._queue.put(event)