"""Network inventory: baseline storage and change reconciliation.

Keeps a persistent record of every device ever seen (MAC as the stable
identity) and compares each scan against it, so the operator can tell at a
glance what is new, what disappeared and -- most importantly -- which
addresses changed hands.

MAC is the identity key, not IP, because DHCP routinely reassigns
addresses. A device that appears with a different MAC than last time is
the signal worth investigating.
"""

from __future__ import annotations

import dataclasses
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from .models import Device

#: Change kinds, most to least urgent.
CHANGE_NEW = "new"
CHANGE_IDENTITY = "identity"
CHANGE_VENDOR = "vendor"
CHANGE_MISSING = "missing"
CHANGE_RETURNING = "returning"
CHANGE_KNOWN = "known"

#: Severity attached to each change kind.
SEVERITY_BY_KIND = {
    CHANGE_IDENTITY: "critical",
    CHANGE_VENDOR: "high",
    CHANGE_NEW: "medium",
    CHANGE_MISSING: "low",
    CHANGE_RETURNING: "info",
    CHANGE_KNOWN: "info",
}


@dataclass(slots=True)
class InventoryRecord:
    """One device tracked in the baseline."""

    mac: str
    ip: str = ""
    vendor: str = ""
    device_type: str = ""
    hostname: str = ""
    first_seen: str = ""
    last_seen: str = ""
    seen_count: int = 0
    approved: bool = False
    #: Last IP the device occupied, used to spot DHCP reassignment.
    previous_ip: str = ""


@dataclass(slots=True)
class InventoryChange:
    """A single difference between the baseline and the current scan."""

    kind: str
    mac: str
    ip: str
    detail: str = ""
    vendor: str = ""
    device_type: str = ""
    first_seen: str = ""
    previous_ip: str = ""

    @property
    def severity(self) -> str:
        return SEVERITY_BY_KIND.get(self.kind, "info")


def storage_path() -> Path:
    """Location of the inventory file."""
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return Path(base) / "IPInspector" / "inventory.json"


class Inventory:
    """
    Persistent device inventory with scan reconciliation.

    The baseline is keyed by MAC. Each :meth:`reconcile` call folds the
    current scan into the store and returns the changes worth reviewing.
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or storage_path()
        self._records: dict[str, InventoryRecord] = {}
        self._loaded = False

    # -- persistence -----------------------------------------------------
    def load(self) -> "Inventory":
        """Read the baseline from disk, ignoring a missing or broken file."""
        if self._loaded:
            return self
        self._loaded = True
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return self

        fields = {f.name for f in dataclasses.fields(InventoryRecord)}
        for mac, entry in (raw.get("devices") or {}).items():
            if not isinstance(entry, dict):
                continue
            # Drop unknown keys so an older file format still loads, and let
            # the dataclass own ``mac`` instead of receiving it twice.
            clean = {k: v for k, v in entry.items() if k in fields and k != "mac"}
            clean["mac"] = str(mac).upper()
            try:
                self._records[str(mac).upper()] = InventoryRecord(**clean)
            except TypeError:
                continue
        return self

    def save(self) -> None:
        """Write the baseline back, ignoring filesystem failures."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "updated": datetime.now().isoformat(timespec="seconds"),
                "devices": {
                    mac: asdict(record) for mac, record in self._records.items()
                },
            }
            self._path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        except OSError:
            pass

    # -- queries ---------------------------------------------------------
    def __len__(self) -> int:
        self.load()
        return len(self._records)

    @property
    def is_empty(self) -> bool:
        self.load()
        return not self._records

    def record(self, mac: str) -> InventoryRecord | None:
        self.load()
        return self._records.get(mac.upper())

    def known_ips(self) -> dict[str, str]:
        self.load()
        """{ip: mac} for every device already in the baseline."""
        return {
            record.ip: mac
            for mac, record in self._records.items()
            if record.ip
        }

    # -- reconciliation --------------------------------------------------
    def reconcile(self, devices: list[Device]) -> list[InventoryChange]:
        """
        Fold a scan into the baseline and return the changes.

        Devices are matched by MAC. A baseline entry not seen in this scan
        is reported as missing rather than deleted, so a device that is
        merely powered off can be told apart from one that disappeared.
        """
        self.load()
        now = datetime.now().isoformat(timespec="seconds")
        changes: list[InventoryChange] = []
        seen: set[str] = set()

        # Which address each MAC used in the previous scan.
        ip_to_mac = self.known_ips()

        for device in devices:
            mac = (device.mac_address or "").upper()
            if not mac:
                # No MAC means the host only answered ICMP/TCP; we cannot
                # track its identity, so it is reported as unverifiable.
                changes.append(
                    InventoryChange(
                        kind=CHANGE_NEW,
                        mac="",
                        ip=device.ip_address,
                        detail="No MAC available (ICMP/TCP discovery only)",
                        vendor=device.vendor,
                        device_type=device.device_type,
                        first_seen=now,
                    )
                )
                continue

            seen.add(mac)
            record = self._records.get(mac)

            if record is None:
                record = InventoryRecord(
                    mac=mac, first_seen=now, approved=False
                )
                self._records[mac] = record
                changes.append(
                    InventoryChange(
                        kind=CHANGE_NEW,
                        mac=mac,
                        ip=device.ip_address,
                        detail="First time seen on this network",
                        vendor=device.vendor,
                        device_type=device.device_type,
                        first_seen=now,
                    )
                )
            else:
                # Same MAC, different address: normal DHCP churn.
                if record.ip and record.ip != device.ip_address:
                    record.previous_ip = record.ip
                elif record.ip != device.ip_address:
                    changes.append(
                        InventoryChange(
                            kind=CHANGE_RETURNING,
                            mac=mac,
                            ip=device.ip_address,
                            detail=f"Back after being absent ({record.ip or 'unknown'} last time)",
                            vendor=device.vendor,
                            device_type=device.device_type,
                            first_seen=record.first_seen,
                            previous_ip=record.ip,
                        )
                    )

                # Same address, different MAC: the interesting case.
                previous_mac = ip_to_mac.get(device.ip_address)
                if previous_mac and previous_mac != mac:
                    changes.append(
                        InventoryChange(
                            kind=CHANGE_IDENTITY,
                            mac=mac,
                            ip=device.ip_address,
                            detail=(
                                f"Address now held by {mac}, previously {previous_mac}"
                            ),
                            vendor=device.vendor,
                            device_type=device.device_type,
                            first_seen=now,
                            previous_ip=device.ip_address,
                        )
                    )

                if record.vendor and device.vendor and record.vendor != device.vendor:
                    changes.append(
                        InventoryChange(
                            kind=CHANGE_VENDOR,
                            mac=mac,
                            ip=device.ip_address,
                            detail=f"Vendor changed: {record.vendor} -> {device.vendor}",
                            vendor=device.vendor,
                            device_type=device.device_type,
                            first_seen=record.first_seen,
                        )
                    )

            record.ip = device.ip_address
            record.vendor = device.vendor
            record.device_type = device.device_type
            record.hostname = device.hostname
            record.last_seen = now
            record.seen_count += 1

        # In the baseline but absent from this scan.
        for mac, record in self._records.items():
            if mac not in seen and record.ip:
                changes.append(
                    InventoryChange(
                        kind=CHANGE_MISSING,
                        mac=mac,
                        ip=record.ip,
                        detail=f"Not seen in this scan (last {record.last_seen or 'unknown'})",
                        vendor=record.vendor,
                        device_type=record.device_type,
                        first_seen=record.first_seen,
                        previous_ip=record.ip,
                    )
                )

        self.save()
        order = {CHANGE_IDENTITY: 0, CHANGE_VENDOR: 1, CHANGE_NEW: 2,
                 CHANGE_RETURNING: 3, CHANGE_MISSING: 4}
        changes.sort(key=lambda c: order.get(c.kind, 9))
        return changes

    # -- management ------------------------------------------------------
    def approve(self, mac: str) -> None:
        """Whitelist a device so future appearances are not flagged as new."""
        self.load()
        record = self._records.get(mac.upper())
        if record is not None:
            record.approved = True
            self.save()

    def forget(self, mac: str) -> None:
        """Drop a device from the baseline entirely."""
        self.load()
        self._records.pop(mac.upper(), None)
        self.save()

    def reset(self) -> None:
        """Clear the baseline; the next scan becomes the new reference."""
        self._records.clear()
        self.save()

    def summary(self, changes: list[InventoryChange]) -> dict[str, int]:
        """Counts per change kind, for the status header."""
        counts: dict[str, int] = {}
        for change in changes:
            counts[change.kind] = counts.get(change.kind, 0) + 1
        counts["total"] = len(self._records)
        return counts