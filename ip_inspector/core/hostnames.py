"""
Name resolution beyond plain reverse DNS.

``gethostbyaddr`` answers only when the address has a PTR record, which on a
corporate LAN is the exception rather than the rule: a printer or a PC joined
by DHCP frequently answers NetBIOS or mDNS and nothing else. Those two
protocols are what the name is *actually* registered as, so querying them
recovers the label an operator would recognise.

Everything here is bounded, best effort and never raises: a name is a
nicety, and a scan must not wait on one.
"""

from __future__ import annotations

import random
import socket
import struct
import threading
import time
from collections import deque
from collections.abc import Sequence

#: Per-query budget. Kept short because a sweep asks this of every host.
NBNS_TIMEOUT = 0.45
MDNS_TIMEOUT = 0.45
#: NetBIOS Name Service and multicast DNS ports.
NBNS_PORT = 137
MDNS_PORT = 5353
#: DNS record type for a NetBIOS node status request.
NBSTAT = 0x0021
#: mDNS "unicast reply" bit: the answer comes back to this socket alone
#: instead of going to the whole segment.
MDNS_UNICAST_RESPONSE = 0x8001


def _encode_name(hostname: str) -> bytes:
    """Encode a dotted name into DNS wire format."""
    out = bytearray()
    for label in hostname.split("."):
        out.append(len(label))
        out += label.encode("ascii", "replace")
    return bytes(out) + b"\x00"


def _skip_name(data: bytes, offset: int) -> int:
    """Advance past a domain name, following a compression pointer."""
    while offset < len(data):
        length = data[offset]
        if length & 0xC0 == 0xC0:              # pointer: two bytes, end of name
            return offset + 2
        if length == 0:
            return offset + 1
        offset += 1 + length
    return offset


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Read a possibly compressed name, returning it and the next offset."""
    labels: list[str] = []
    jumped = False
    end = offset
    while offset < len(data):
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if not jumped:
                end = offset + 2
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            offset = pointer
            jumped = True
            continue
        if length == 0:
            return ".".join(labels), (end if jumped else offset + 1)
        labels.append(data[offset + 1 : offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    return ".".join(labels), end


def reverse_dns(ip: str, timeout: float = 0.8) -> str:
    """The PTR name for an address, or "" when there is none.

    ``timeout`` is part of the signature for symmetry with the other probes
    but cannot be enforced from here: ``gethostbyaddr`` is a call into the OS
    resolver, which runs its own deadline and ignores the socket timeout (see
    :func:`resolve_many`, which is what actually bounds this phase).

    The process-wide default socket timeout is deliberately left untouched.
    It is a single global value, and :func:`resolve_many` puts a hundred-odd
    resolver threads in flight at once: writing it here would hand every other
    thread in the program -- the port scanner included -- a deadline nobody
    asked for, and the ``finally`` restore would write back a value another
    thread had already changed, leaking the timeout past this call. Sockets
    that need a deadline set it on themselves.
    """
    try:
        return socket.gethostbyaddr(ip)[0].strip().rstrip(".")
    except (socket.herror, socket.gaierror, OSError):
        return ""

def _parse_nbns(data: bytes, transaction: int) -> str:
    """
    Pull the machine name out of an NBSTAT answer.

    The reply lists every name the node has registered; the first one is the
    computer name itself and the rest are usually suffixes, so the first entry
    is taken and the group name marker dropped.
    """
    if len(data) < 12 or struct.unpack("!H", data[:2])[0] != transaction:
        return ""
    questions, answers = struct.unpack("!HH", data[4:8])
    offset = 12
    for _ in range(questions):
        # Not _skip_name: a NetBIOS name is a raw sixteen byte field, not a
        # length-prefixed DNS one, and it can never be compressed. Walking it
        # as DNS lands 33 bytes past the question and loses the answer.
        offset += 16 + 4

    for _ in range(answers or 0):
        offset = _skip_name(data, offset)
        if offset + 10 > len(data):
            return ""
        record_type = struct.unpack("!H", data[offset : offset + 2])[0]
        length = struct.unpack("!H", data[offset + 8 : offset + 10])[0]
        payload = data[offset + 10 : offset + 10 + length]
        offset += 10 + length
        if record_type != NBSTAT or not payload:
            continue
        # RDATA: a count, then 15-byte names each followed by a suffix byte,
        # then a zero terminator.
        for index in range(payload[0]):
            start = 1 + index * 16
            chunk = payload[start : start + 15]
            if len(chunk) < 15 or not chunk.strip(b"\x00"):
                continue
            name = chunk.decode("ascii", "replace").strip(" \x00")
            if name and "GROUP" not in name.upper():
                return name
    return ""


def netbios_name(ip: str, timeout: float = NBNS_TIMEOUT) -> str:
    """
    Ask the NetBIOS Name Service who lives at this address.

    Unicast to the host rather than to 255.255.255.255: the answer comes back
    to one socket instead of the whole segment, and hosts with a firewall do
    not have to answer a broadcast aimed at everyone.
    """
    try:
        socket.inet_aton(ip)
    except OSError:
        return ""

    transaction = random.randint(0, 0xFFFF)
    # 0x20 length prefix, then '*' padded to the 15 bytes of a NetBIOS name.
    query_name = b"\x20\x2a" + b"\x00" * 14
    packet = (
        struct.pack("!HHHHHH", transaction, 0, 1, 0, 0, 0)
        + query_name
        + struct.pack("!HH", NBSTAT, 1)
    )

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (ip, NBNS_PORT))
            data, _ = sock.recvfrom(1024)
    except (socket.timeout, OSError):
        return ""
    return _parse_nbns(data, transaction).rstrip(".")


def _parse_mdns(data: bytes, transaction: int) -> str:
    """Pull the first PTR answer out of an mDNS reply."""
    if len(data) < 12 or struct.unpack("!H", data[:2])[0] != transaction:
        return ""
    questions, answers = struct.unpack("!HH", data[4:8])
    offset = 12
    for _ in range(questions):
        offset = _skip_name(data, offset) + 4

    for _ in range(answers or 0):
        offset = _skip_name(data, offset)
        if offset + 10 > len(data):
            return ""
        record_type = struct.unpack("!H", data[offset : offset + 2])[0]
        length = struct.unpack("!H", data[offset + 8 : offset + 10])[0]
        payload = data[offset + 10 : offset + 10 + length]
        offset += 10 + length
        if record_type == 12 and payload:      # PTR
            name, _ = _read_name(data, offset - length)
            short = name.replace(".local", "").replace(".in-addr.arpa", "")
            return short.strip(".") or name.strip(".")
    return ""


def mdns_name(ip: str, timeout: float = MDNS_TIMEOUT) -> str:
    """
    Ask the multicast DNS responder at this address for its hostname.

    Sent unicast to the host, because a query to 224.0.0.251 wakes every
    Bonjour device on the segment and the responder on the target answers
    either way.
    """
    octets = ip.split(".")
    if len(octets) != 4:
        return ""
    transaction = random.randint(0, 0xFFFF)
    question = _encode_name(".".join(reversed(octets)) + ".in-addr.arpa.local")
    packet = (
        struct.pack("!HHHHHH", transaction, 0, 1, 0, 0, 0)
        + question
        + struct.pack("!HH", 12, MDNS_UNICAST_RESPONSE)
    )

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (ip, MDNS_PORT))
            data, _ = sock.recvfrom(1024)
    except (socket.timeout, OSError):
        return ""
    return _parse_mdns(data, transaction)


def resolve_name(ip: str) -> str:
    """
    Best name available for an address: PTR, then NetBIOS, then mDNS.

    The order matters. A PTR record is the administratively correct name and
    wins even when the device also advertises a stale NetBIOS one.
    """
    return reverse_dns(ip) or netbios_name(ip) or mdns_name(ip)


#: Threads used to resolve a whole sweep, and the seconds the sweep may spend.
#: Raised from 48 so a /24 resolves names in one wave instead of several,
#: since threads mostly wait on the network. Daemon threads are deliberate:
#: a resolver stuck inside the OS cannot be killed, and a pool of ordinary
#: threads would keep the interpreter alive at exit.
RESOLVE_WORKERS = 128
#: Total budget for the name phase of a sweep. Kept short: names are a
#: nicety and must never dominate the scan time.
RESOLVE_BUDGET = 4.0

#: Budget for a single address: PTR, NetBIOS and mDNS each answer well under
#: half a second on a LAN when they answer at all; anything slower is a dead
#: address holding a thread that could be resolving the next host.
SINGLE_NAME_BUDGET = 1.0


def resolve_many(
    ips: Sequence[str], workers: int = RESOLVE_WORKERS, budget: float = RESOLVE_BUDGET
) -> dict[str, str]:
    """
    Resolve a batch of addresses at once and return the names that came back.

    Sequential resolution is not an option here. ``gethostbyaddr`` runs on the
    operating system resolver, which ignores the socket timeout: one dead
    address can block for seconds, and a /24 would take minutes. The lookups
    therefore run on daemon threads and the caller waits at most ``budget``.

    Daemon threads are deliberate. A resolver stuck inside the OS cannot be
    killed, and a pool of ordinary threads would keep the interpreter alive at
    exit; these simply go away with the process. A name that misses the
    deadline stays blank, exactly as it did when the lookup failed.
    """
    remaining = deque(ip for ip in ips if ip)
    if not remaining:
        return {}

    names: dict[str, str] = {}
    lock = threading.Lock()
    deadline = time.monotonic() + budget

    def worker() -> None:
        while True:
            with lock:
                if not remaining or time.monotonic() >= deadline:
                    return
                ip = remaining.popleft()
            # A per-address budget on top of the global one: a single dead
            # address must not burn the whole sweep budget while the rest of
            # the queue waits. Names are best effort; a miss stays blank.
            address_deadline = time.monotonic() + SINGLE_NAME_BUDGET
            try:
                name = resolve_name(ip)
            except Exception:  # noqa: BLE001 - a name is never worth a crash
                continue
            if time.monotonic() >= address_deadline:
                # Too slow to matter for a fast sweep; treat as unresolved.
                continue
            if name:
                names[ip] = name

    threads = [
        threading.Thread(target=worker, daemon=True, name=f"resolve-{index}")
        for index in range(max(1, min(workers, len(ips))))
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(max(0.0, deadline - time.monotonic()))
    return names

