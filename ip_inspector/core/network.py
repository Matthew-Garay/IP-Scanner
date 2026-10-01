"""Network scanning engine: host discovery, port probing and classification.

Responsibilities
----------------
* Layer 2 discovery: ARP sweep via scapy, with an OS-table fallback.
* Layer 4 probing: concurrent asyncio TCP connect scan.
* Device fingerprinting from open ports, TTL and vendor.
* Progress reporting through a thread-safe queue.

This module must never import the user interface. It knows nothing about
widgets; the UI drains :class:`ScannerEvent` records from the queue.

Dependencies: models (data only), utils (platform helpers) and ping (the
system ping binary, for the TTL that fingerprints the operating system).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import queue
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Sequence

from .identify import (
    BANNER_GRACE,
    BANNER_PORTS,
    BANNER_PROBES,
    HTTP_PORTS,
    identify_camera,
    identify_model,
    os_from_fingerprint,
    service_version,
    summarise_banner,
)
from .hostnames import resolve_many
from .inventory import Inventory
from .models import (
    KNOWN_SERVICES,
    Device,
    Port,
    ScanRequest,
    ScannerEvent,
)
from .ping import ping_ttl
from .utils import (
    is_elevated,
    is_ip_in_virtual_subnet,
    iter_local_ipv4,
    lookup_vendor,
    plan_targets,
    read_arp_cache,
    supports_layer2,
)

logger = logging.getLogger(__name__)

#: Upper bound on targets per ARP batch, protecting against /8 mishaps.
MAX_ARP_BATCH = 4096

#: Name resolution lives in :mod:`ip_inspector.hostnames`, and that is where
#: the scan is really bounded. This constant used to claim a per-lookup limit
#: that never existed: the OS resolver ignores the socket timeout, so a dead
#: address blocked for seconds anyway.
HOSTNAME_TIMEOUT = 1.5

#: Raw SYN probes used to read TCP windows, and how long each one waits.
#: Bumped workers so a /24 finishes in one wave instead of three; the
#: timeout is cut because a stack that answers does so immediately and a
#: silent one is not worth waiting on.
WINDOW_WORKERS = 16
WINDOW_TIMEOUT = 0.5

#: System ping calls used to read a TTL when ICMP needs no elevation.
#: Each lookup is one `ping -n 1` process; 64 parallel processes still cost
#: less than one extra wave of 1-second waits on a /24.
PING_WORKERS = 64
TTL_TIMEOUT = 0.7

#: Budget for the model-identification phase. Identification is best effort:
#: HTTP titles, ONVIF descriptions and RTSP banners must never dominate the
#: sweep, so each device is capped here even when its web server stalls.
IDENTIFY_WORKERS = 32
IDENTIFY_TIMEOUT = 2.5
IDENTIFY_HTTP_TIMEOUT = 0.8

#: Lines of an HTTP response read while grabbing a banner; the headers end
#: long before this, and a service that rambles is cut off there.
HTTP_HEADER_LINES = 24

#: Ports probed to decide whether a host is alive when ICMP is unavailable.
REACHABILITY_PORTS: tuple[int, ...] = (445, 135, 3389, 22, 80, 443, 8080)

#: Fast-path liveness ports for the reachability pre-check. These fire first
#: with a very short timeout; only hosts that miss all of them pay for the
#: wider REACHABILITY_PORTS sweep. Ordered by LAN hit rate (SMB/RDP/SSH
#: answer fast on Windows/Linux; HTTP(S) covers printers/cameras/IoT).
FAST_LIVENESS_PORTS: tuple[int, ...] = (445, 135, 3389, 22)

#: Timeout for the fast-path liveness ports. Kept deliberately short: an
#: alive host on a LAN answers in milliseconds, so anything slower is either
#: dead or filtered and belongs in the full sweep anyway.
FAST_LIVENESS_TIMEOUT = 0.15


class NetworkScanner:
    """
    Orchestrates discovery and port probing for a target range.

    Threading contract
    ------------------
    :meth:`run_scan` blocks and must run on a worker thread. It never
    touches tkinter; every update travels through ``event_queue``, which
    is safe to write from any thread.
    """

    def __init__(self, event_queue: queue.Queue[ScannerEvent] | None = None) -> None:
        self.event_queue: queue.Queue[ScannerEvent] = event_queue or queue.Queue()
        self._stop_event = threading.Event()
        self.inventory = Inventory()
        self.inventory_changes: list = []

    # ------------------------------------------------------------------
    # Cancellation
    # ------------------------------------------------------------------
    def stop(self) -> None:
        """Request cancellation; honoured between phases and devices."""
        self._stop_event.set()

    def reset(self) -> None:
        self._stop_event.clear()

    @property
    def is_stopping(self) -> bool:
        return self._stop_event.is_set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def run_scan(self, request: ScanRequest) -> list[Device]:
        """Execute a full scan and return the discovered devices."""
        self.reset()
        plan = plan_targets(request.target_range)
        targets = plan.addresses()
        if not targets:
            self._emit(ScannerEvent("Error", "Invalid or empty target range", is_error=True))
            return []

        self._emit(ScannerEvent("Discovery", f"Scanning {len(targets)} addresses", 0, len(targets)))
        devices = self._discover(targets, request)

        self._enrich(devices, request)
        if request.scan_ports_enabled and not self.is_stopping:
            self._scan_ports(devices, request)
        self._tcp_windows(devices)
        self._classify_all(devices)

        # Model identification runs last: it needs the final open-port set.
        if request.identify_models and not self.is_stopping:
            self._identify_models(devices, request)

        for device in devices:
            self._emit(ScannerEvent("Device", device=device))

        self._emit(
            ScannerEvent("Cancelled", "Scan stopped by user")
            if self.is_stopping
            else ScannerEvent("Finished", f"{len(devices)} devices found")
        )

        self._reconcile_inventory(devices)

        devices.sort(key=lambda device: int(ipaddress.ip_address(device.ip_address)))
        return devices

    def _reconcile_inventory(self, devices: list[Device]) -> None:
        """Diff the scan against the stored inventory baseline."""
        self._emit(ScannerEvent("Inventory", "Comparing against inventory"))
        try:
            changes = self.inventory.reconcile(devices)
        except Exception:  # noqa: BLE001 - never fail a scan over the baseline
            logger.debug("Inventory reconciliation failed", exc_info=True)
            self.inventory_changes = []
            return

        self.inventory_changes = changes
        flagged = {change.mac for change in changes if change.kind == "new"}
        for device in devices:
            mac = (device.mac_address or "").upper()
            if mac in flagged:
                device.inventory_state = "new"
                device.first_seen = next(
                    c.first_seen for c in changes
                    if c.kind == "new" and c.mac == mac
                )
        self._emit(ScannerEvent("Inventory", f"{len(changes)} inventory changes"))

    # ------------------------------------------------------------------
    # Event plumbing
    # ------------------------------------------------------------------
    def _emit(self, event: ScannerEvent) -> None:
        self.event_queue.put(event)
    # ------------------------------------------------------------------
    # Phase 1: discovery (layers 2, 3 and 4)
    # ------------------------------------------------------------------
    def _discover(self, targets: list[str], request: ScanRequest) -> list[Device]:
        """ARP sweep first, then a reachability probe for the remaining IPs."""
        arp_table = self._arp_sweep(targets, request.interface)
        pending = [ip for ip in targets if ip not in arp_table]
        reachable = self._probe_reachability(pending, request.port_timeout, request.concurrency)

        devices: list[Device] = []
        for ip in targets:
            mac = arp_table.get(ip)
            if not mac and ip not in reachable:
                continue
            latency, ttl = reachable.get(ip, (None, None))
            devices.append(
                Device(
                    ip_address=ip,
                    mac_address=mac,
                    discovery_method="ARP" if mac else "TCP",
                    response_time_ms=latency,
                    ttl=ttl,
                    is_vpn_active=is_ip_in_virtual_subnet(ip),
                )
            )
        # ICMP needs elevation; without it the TTL comes from the system ping
        # so the fingerprint still has something to work with.
        self._fill_missing_ttls(devices, min(request.port_timeout, 1.0))
        return devices

    def _arp_sweep(self, targets: list[str], interface: str = "") -> dict[str, str]:
        """
        Broadcast ARP requests and collect ``{ip: mac}``.

        Needs elevated rights *and* a layer-2 backend. When either is
        missing we fall back to the OS neighbour table so the scan still
        returns MAC addresses where the system already knows them.

        ``interface`` pins both the socket and the subnet decision to one
        adapter, which is what stops a VPN or a second NIC from eating the
        sweep. scapy resolves a Windows friendly name such as "Wi-Fi" to its
        own device id, so the name the selector shows is the name we pass.
        """
        if not (is_elevated() and supports_layer2()):
            logger.info("Layer-2 unavailable; falling back to the OS ARP table.")
            known = read_arp_cache()
            return {ip: mac for ip, mac in known.items() if ip in set(targets)}

        networks = self._scannable_networks(targets, interface)
        if not networks:
            return read_arp_cache()

        try:
            from scapy.all import ARP, Ether, srp
        except ImportError:
            return read_arp_cache()

        table: dict[str, str] = {}
        try:
            for network in networks:
                if self.is_stopping:
                    break
                batch = [
                    ip
                    for ip in targets
                    if ipaddress.ip_address(ip) in network
                ][:MAX_ARP_BATCH]
                if not batch:
                    continue
                answered, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=batch),
                    timeout=2.0,
                    verbose=0,
                    **({"iface": interface} if interface else {}),
                )
                for _request, response in answered:
                    table[response[ARP].psrc] = response[Ether].src
        except Exception:  # noqa: BLE001 - permission, driver or capture failure
            logger.warning("ARP sweep failed; using the OS ARP table.", exc_info=True)
            return read_arp_cache()
        return table

    @staticmethod
    def _scannable_networks(
        targets: Sequence[str], interface: str = ""
    ) -> list[ipaddress.IPv4Network]:
        """
        Private subnets we own an interface on, where ARP applies.

        Only the selected adapter is consulted, so a target range that
        belongs to another NIC never turns into a broadcast on this one.
        """
        local = [
            ipaddress.ip_network(f"{ip}/{mask}", strict=False)
            for ip, mask in iter_local_ipv4(interface)
        ]
        selected: set[ipaddress.IPv4Network] = set()
        for ip in targets:
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                continue
            for network in local:
                if address in network and network.is_private:
                    selected.add(ipaddress.ip_network(f"{address}/24", strict=False))
                    break
        return sorted(selected)

    def _probe_reachability(
        self, ips: list[str], timeout: float, concurrency: int
    ) -> dict[str, tuple[float, int | None]]:
        """Detect live hosts, with the TTL each one answered when it gave one."""
        if not ips:
            return {}
        try:
            return asyncio.run(
                self._probe_all(ips, timeout, concurrency)
            )
        except RuntimeError:
            # An event loop is already running on this thread; skip the probe.
            logger.debug("Nested event loop detected; skipping reachability probe.")

    async def _probe_all(
        self, ips: list[str], timeout: float, concurrency: int
    ) -> dict[str, tuple[float, int | None]]:
        semaphore = asyncio.Semaphore(max(1, concurrency))
        alive: dict[str, tuple[float, int | None]] = {}

        async def worker(ip: str) -> None:
            async with semaphore:
                if self.is_stopping:
                    return
                seen = await self._icmp_ping(ip, timeout)
                latency, ttl = seen if seen else (None, None)
                if latency is None:
                    for port in REACHABILITY_PORTS:
                        latency = await self._tcp_ping(ip, port, timeout)
                        if latency is not None:
                            break
            if latency is not None:
                alive[ip] = (latency, ttl)

        await asyncio.gather(*(worker(ip) for ip in ips))
        return alive

    def _fill_missing_ttls(self, devices: list[Device], timeout: float) -> None:
        """
        Read the TTL of hosts the ICMP path could not answer for.

        scapy needs elevation; the system ping does not. Running it only for
        hosts that are already known to be alive keeps the cost proportional
        to the devices that actually exist, not to the size of the range.
        """
        pending = [device for device in devices if device.ttl is None]
        if not pending:
            return

        with ThreadPoolExecutor(max_workers=PING_WORKERS,
                                thread_name_prefix="ping-ttl") as pool:
            futures = {
                pool.submit(ping_ttl, device.ip_address, timeout): device
                for device in pending
            }
            for future, device in futures.items():
                if self.is_stopping:
                    break
                try:
                    device.ttl = future.result(timeout=timeout + 4.0)
                except Exception:  # noqa: BLE001 - an absent TTL is not an error
                    device.ttl = None

    # ------------------------------------------------------------------
    # Phase 2: port probing (layer 4)
    # ------------------------------------------------------------------
    async def _probe_port(self, ip: str, port_number: int, timeout: float) -> Port:
        """Classify one TCP port as open, closed or filtered."""
        loop = asyncio.get_running_loop()
        started = loop.time()
        service = KNOWN_SERVICES.get(port_number, "")

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port_number), timeout=timeout
            )
        except asyncio.TimeoutError:
            return Port(port_number, "filtered", service)
        except ConnectionRefusedError:
            latency = round((loop.time() - started) * 1000, 2)
            return Port(port_number, "closed", service, latency_ms=latency)
        except (OSError, ConnectionError):
            return Port(port_number, "filtered", service)

        latency = round((loop.time() - started) * 1000, 2)
        # The connection is already open, so the greeting is free: no second
        # connect, no extra traffic on the wire.
        banner = await self._read_banner(reader, writer, port_number)
        await self._close_writer(writer)
        return Port(port_number, "open", service, banner=banner,
                    version=service_version(banner), latency_ms=latency)

    async def _read_banner(
        self, reader, writer, port_number: int
    ) -> str:
        """
        Capture the greeting a service volunteers on connect.

        Reading is line by line on purpose. ``StreamReader.read(n)`` waits for
        *n* bytes rather than for whatever has arrived, so asking for 200
        against a 30 byte PostgreSQL greeting just times out and reports a
        silent service. A line is the natural unit for every protocol here.

        The whole read shares one deadline: a service that has nothing to say
        is treated as having said nothing instead of holding up the sweep.
        """
        if port_number not in BANNER_PORTS:
            return ""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + BANNER_GRACE

        try:
            nudge = BANNER_PROBES.get(port_number)
            if nudge:
                writer.write(nudge)
                await writer.drain()
        except (OSError, ConnectionError):
            return ""

        is_http = port_number in HTTP_PORTS
        chunks: list[bytes] = []
        for _ in range(HTTP_HEADER_LINES if is_http else 1):
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=remaining)
            except asyncio.IncompleteReadError as exc:
                # The peer closed mid-line; whatever arrived is still the
                # greeting, and a binary protocol may never send a newline.
                if exc.partial:
                    chunks.append(exc.partial)
                break
            except (asyncio.TimeoutError, asyncio.LimitOverrunError,
                    OSError, ConnectionError):
                break
            chunks.append(line)
            if is_http and line in (b"\r\n", b"\n"):
                break                       # end of the response headers
        return summarise_banner(b"".join(chunks), port_number)

    def _identify_models(self, devices: list[Device],
                         request: ScanRequest) -> None:
        """Fill in the model field for every device, best effort.

        Identification is a fan-out: every device is probed on its own web
        ports, and a host that never answers costs the full HTTP timeout each
        time. Walking the list in order therefore made the phase grow linearly
        with the sweep -- a /24 of closed addresses spent minutes here, which
        is what left the window looking stuck even though the UI thread was
        free. The work is independent per device, so it goes out on a pool
        and costs one wave instead of a queue.

        Each device is also capped: :data:`IDENTIFY_TIMEOUT` is the ceiling on
        a single identification no matter how many ports it probes, so a
        device that answers slowly cannot extend the phase on its own.
        """
        if not devices:
            return
        self._emit(ScannerEvent("Models", f"Identifying {len(devices)} devices"))

        def identify(device: Device) -> None:
            open_ports = [p.number for p in device.open_ports if p.is_open]
            if "IP Camera" in request.device_hints:
                model, vendor = identify_camera(device.ip_address, open_ports)
                if model:
                    device.model = model
                if vendor and not device.vendor:
                    device.vendor = vendor
            if not device.model:
                device.model = identify_model(
                    device.ip_address,
                    device.hostname,
                    device.vendor,
                    open_ports,
                    timeout=IDENTIFY_HTTP_TIMEOUT,
                )

        workers = max(1, min(IDENTIFY_WORKERS, len(devices)))
        with ThreadPoolExecutor(max_workers=workers,
                                thread_name_prefix="identify") as pool:
            futures = {
                pool.submit(identify, device): device for device in devices
            }
            for future, device in futures.items():
                if self.is_stopping:
                    break
                try:
                    # The cap is a backstop, not the expected wait: a device
                    # that outruns it is left without a model rather than
                    # holding the phase open.
                    future.result(timeout=IDENTIFY_TIMEOUT)
                except Exception:  # noqa: BLE001 - a model is a nicety
                    logger.debug("Model identification failed for %s",
                                 device.ip_address, exc_info=True)
                self._emit(ScannerEvent("Device", device=device))

    def _scan_ports(self, devices: list[Device], request: ScanRequest) -> None:
        """Synchronous entry point that drives the concurrent port scan."""
        if not devices:
            return
        try:
            asyncio.run(
                self._scan_ports_concurrently(devices, request)
            )
        except RuntimeError:
            logger.debug("Nested event loop; port scan skipped.")

    async def _scan_ports_concurrently(
        self, devices: list[Device], request: ScanRequest
    ) -> None:
        """Probe every device under a single global concurrency cap.

        Each (host, port) pair is its own task rather than each host walking
        its ports in turn. A host probed sequentially spends one full timeout
        per closed port, so a 1024-port sweep of a single machine took the
        timeout multiplied by 1024 -- twenty minutes -- while the semaphore
        sat idle because a single worker could only ever hold one permit.
        One task per pair lets the cap actually mean something.
        """
        total = len(devices) * len(request.ports)
        self._emit(ScannerEvent("Ports", f"Probing {len(request.ports)} ports", 0, total))

        semaphore = asyncio.Semaphore(max(1, request.concurrency))
        results: dict[str, list[Port]] = {d.ip_address: [] for d in devices}
        completed = 0

        async def probe(device: Device, port_number: int) -> None:
            nonlocal completed
            if self.is_stopping:
                return
            async with semaphore:
                port = await self._probe_port(
                    device.ip_address, port_number, request.port_timeout
                )
            results[device.ip_address].append(port)
            completed += 1
            # Progress is emitted as the sweep runs so the bar moves, but only
            # every so often: one event per port would flood the queue the UI
            # drains, which is its own kind of freeze.
            if completed % 100 == 0 or completed == total:
                self._emit(ScannerEvent("Ports", "", completed, total))

        await asyncio.gather(
            *(probe(device, port) for device in devices
              for port in request.ports)
        )

        for device in devices:
            device.open_ports = sorted(
                results[device.ip_address], key=lambda port: port.number
            )
        self._emit(ScannerEvent("Ports", "Port scan complete", total, total))

    async def _tcp_ping(self, ip: str, port: int, timeout: float) -> float | None:
        """Latency in milliseconds if the port accepts a connection."""
        loop = asyncio.get_running_loop()
        started = loop.time()
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
        except (OSError, asyncio.TimeoutError, ConnectionError):
            return None
        await self._close_writer(writer)
        return round((loop.time() - started) * 1000, 2)

    async def _icmp_ping(self, ip: str, timeout: float) -> tuple[float, int | None] | None:
        """
        ICMP echo via scapy, executed off-loop because it blocks.

        Returns the round trip time and the TTL the reply carried, which is
        the raw material of the OS fingerprint. Needs elevation, so the
        caller has a fallback for when this returns nothing.
        """
        if not is_elevated():
            return None
        loop = asyncio.get_running_loop()
        started = loop.time()

        def _send() -> object | None:
            try:
                from scapy.all import ICMP, IP, sr1

                return sr1(IP(dst=ip) / ICMP(), timeout=timeout, verbose=0)
            except Exception:  # noqa: BLE001 - raw socket not permitted
                return None

        answer = await loop.run_in_executor(None, _send)
        if answer is None:
            return None
        return round((loop.time() - started) * 1000, 2), int(getattr(answer, "ttl", 0)) or None

    @staticmethod
    async def _close_writer(writer: asyncio.StreamWriter) -> None:
        """Close a socket without letting teardown errors escape."""
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionResetError):
            pass

    # ------------------------------------------------------------------
    # Phase 3: enrichment and classification
    # ------------------------------------------------------------------
    def _enrich(self, devices: list[Device], request: ScanRequest) -> None:
        """Attach vendor and hostname to each discovered device."""
        for device in devices:
            if self.is_stopping:
                break
            device.vendor = lookup_vendor(device.mac_address)

        if request.resolve_hostnames and not self.is_stopping:
            # One concurrent pass instead of a lookup per row: the OS resolver
            # ignores socket timeouts, so a dead address would otherwise stall
            # the whole table.
            names = resolve_many([device.ip_address for device in devices])
            for device in devices:
                device.hostname = names.get(device.ip_address, "")

        for device in devices:
            self._emit(ScannerEvent("Device", device=device))

    _WINDOWS_PORTS = frozenset({135, 139, 445, 3389})
    _LINUX_PORTS = frozenset({22, 3306, 5432, 6379, 9090})
    _ROUTER_PORTS = frozenset({53, 1900, 49152, 7547})
    _IOT_PORTS = frozenset({1883, 8883, 554, 34567})
    _PRINTER_PORTS = frozenset({631, 9100})

    _VENDOR_HINTS: tuple[tuple[str, str], ...] = (
        ("raspberry", "Raspberry Pi"),
        ("apple", "Apple Device"),
        ("hewlett", "Server"),
        ("cisco", "Network Device"),
        ("d-link", "Router"),
        ("netgear", "Router"),
        ("tp-link", "Router"),
        ("hikvision", "IP Camera"),
    )

    def _tcp_windows(self, devices: list[Device]) -> None:
        """
        Read the advertised TCP window of each device, where that is possible.

        The window is half of the fingerprint but it only appears in the
        SYN-ACK, so it costs one raw SYN per host. Without elevation or a
        layer-2 driver it simply cannot be seen, and the TTL carries the guess
        on its own rather than the scan pretending to know more than it does.
        """
        if not (is_elevated() and supports_layer2()) or self.is_stopping:
            return
        targets = [
            (device, next((p.number for p in device.open_ports if p.is_open), None))
            for device in devices
        ]
        targets = [(device, port) for device, port in targets if port]
        if not targets:
            return

        self._emit(ScannerEvent("Fingerprint", f"Reading TCP windows on {len(targets)} hosts"))
        with ThreadPoolExecutor(max_workers=WINDOW_WORKERS,
                                thread_name_prefix="tcp-window") as pool:
            futures = {
                pool.submit(self._window_of, device.ip_address, port): device
                for device, port in targets
            }
            for future, device in futures.items():
                if self.is_stopping:
                    break
                try:
                    device.tcp_window = future.result(timeout=WINDOW_TIMEOUT)
                except Exception:  # noqa: BLE001 - a fingerprint is optional
                    device.tcp_window = None

    @staticmethod
    def _window_of(ip: str, port: int) -> int | None:
        """Advertised window from a SYN-ACK, or None when there is no answer."""
        from scapy.all import IP, TCP, sr1

        answer = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=WINDOW_TIMEOUT)
        if answer is None or not answer.haslayer(TCP):
            return None
        # 0x12 is SYN+ACK. A RST means the port is closed and says nothing
        # about the stack, so it is treated as no answer at all.
        if not int(answer[TCP].flags) & 0x12:
            return None
        return int(answer[TCP].window)

    def _classify_all(self, devices: list[Device]) -> None:
        for device in devices:
            self._classify(device)

    def _classify(self, device: Device) -> None:
        """Derive a human device type from open ports and vendor."""
        open_ports = {port.number for port in device.open_ports if port.is_open}
        scores: dict[str, float] = {}

        def boost(label: str, points: float) -> None:
            scores[label] = scores.get(label, 0.0) + points

        # The OS guess is kept on the device as well as feeding the type, so
        # the model column can still say something when no model is known.
        device.os_name = os_from_fingerprint(
            device.ttl, device.tcp_window, list(open_ports), device.vendor)
        if device.os_name == "Windows":
            boost("Windows PC", 1.0)
        elif device.os_name in ("Linux/Unix", "Apple device"):
            boost("Linux Server", 0.8)
        elif device.os_name == "Network device":
            boost("Network Device", 1.0)

        for ports, label in (
            (self._WINDOWS_PORTS, "Windows PC"),
            (self._LINUX_PORTS, "Linux Server"),
            (self._ROUTER_PORTS, "Router"),
            (self._IOT_PORTS, "IoT Device"),
            (self._PRINTER_PORTS, "Printer"),
        ):
            if open_ports & ports:
                boost(label, 3.0 if label != "Printer" else 4.0)

        vendor = device.vendor.lower()
        for keyword, label in self._VENDOR_HINTS:
            if keyword in vendor:
                boost(label, 2.0)
                break

        if device.ttl is not None:
            if device.ttl >= 100:
                boost("Windows PC", 1.0)
            elif device.ttl >= 50:
                boost("Linux Server", 0.8)

        if scores:
            device.device_type = max(scores.items(), key=lambda item: item[1])[0]
