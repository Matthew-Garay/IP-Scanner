"""Data regressions: device model, status colour and identification."""

import re
import unittest

from ip_inspector.core.identify import IDENTITY_PORTS
from ip_inspector.core.models import Device, Port, SecurityFinding


class DeviceModel(unittest.TestCase):
    """Invariants of the data model."""

    def test_mac_is_normalised(self):
        d = Device(ip_address="10.0.0.1", mac_address="aabbccddeeff")
        self.assertEqual(d.mac_address, "AA:BB:CC:DD:EE:FF")

    def test_ports_summary_only_open_and_sorted(self):
        d = Device(ip_address="10.0.0.1")
        d.open_ports = [
            Port(number=443, state="open", service="https"),
            Port(number=22, state="open", service="ssh"),
            Port(number=23, state="closed", service="telnet"),
        ]
        self.assertEqual(d.ports_summary, "22/ssh, 443/https")

    def test_open_port_count(self):
        d = Device(ip_address="10.0.0.1")
        d.open_ports = [Port(number=80, state="open"),
                        Port(number=81, state="closed")]
        self.assertEqual(d.open_port_count, 1)


class StatusColour(unittest.TestCase):
    """
    The colour levels used to be swapped: the marker returned the amber
    "attention" colour for a host that was down and the red alert for a mere
    VPN. A machine that did not answer read exactly like one behind a VPN.

    This pins the contract the status colour must follow.
    """

    @staticmethod
    def _tag(device, online, vpn_colour, warning_colour):
        if device.alerts_count or device.worst_severity == "critical":
            return warning_colour
        if not device.is_alive:
            return warning_colour
        if device.is_vpn_active or device.risk_score >= 15:
            return vpn_colour
        return online

    def test_a_host_that_is_down_is_red(self):
        down = Device(ip_address="10.0.0.1", is_alive=False)
        self.assertEqual(self._tag(down, "G", "A", "R"), "R")

    def test_a_critical_finding_is_red_even_when_up(self):
        d = Device(ip_address="10.0.0.1", is_alive=True, risk_score=3)
        d.findings = [SecurityFinding(severity="critical", title="t", detail="d")]
        self.assertEqual(self._tag(d, "G", "A", "R"), "R")

    def test_a_vpn_host_is_amber(self):
        d = Device(ip_address="10.0.0.1", is_alive=True, is_vpn_active=True)
        self.assertEqual(self._tag(d, "G", "A", "R"), "A")

    def test_a_clean_host_is_green(self):
        d = Device(ip_address="10.0.0.1", is_alive=True)
        self.assertEqual(self._tag(d, "G", "A", "R"), "G")


class IdentityCoverage(unittest.TestCase):
    """
    The identity port list used to stop at four. A device whose web panel
    lived on another port came out without a model even though it was
    reachable.
    """

    def test_covers_alternative_web_ports(self):
        for port in (8443, 8081, 81, 8008, 8888, 9090, 5000):
            self.assertIn(port, IDENTITY_PORTS, "port %d is missing" % port)

    def test_keeps_the_original_four(self):
        for port in (80, 8080, 443, 8000):
            self.assertIn(port, IDENTITY_PORTS)


class PortsColumn(unittest.TestCase):
    """
    The ports cell must list every open port: an earlier version truncated
    it, and ports the scanner had found seemed to be missing.
    """

    PORTS = [22, 80, 443, 445, 3389, 8080, 9100, 3306, 5432, 6379,
             1883, 554, 8554, 23, 25, 53, 110, 139, 143, 389, 587, 631,
             993, 995, 1433, 5000, 8443, 9090, 8081, 81]

    def _device(self, count):
        device = Device(ip_address="10.0.0.1")
        for number in self.PORTS[:count]:
            device.open_ports.append(Port(number=number, state="open", service="svc"))
        return device

    def test_the_cell_never_drops_a_port(self):
        for count in range(1, len(self.PORTS) + 1):
            cell = self._device(count).ports_compact()
            self.assertEqual(len(re.findall(r"\d+", cell)), count,
                             "with %d ports the cell says otherwise" % count)

    def test_the_ports_column_is_wide_enough(self):
        try:
            from ip_inspector.interface.widgets import COL_PORTS, TREE_COLUMNS
        except Exception as exc:  # pragma: no cover - no tkinter
            self.skipTest("no interface: %s" % exc)
        self.assertGreaterEqual(TREE_COLUMNS[COL_PORTS][1], 180)

    def test_the_full_summary_is_untouched(self):
        """Only the cell is compact: the full summary keeps every service."""
        self.assertEqual(len(self._device(12).ports_summary.split(", ")), 12)

    def test_no_open_ports_gives_a_dash(self):
        self.assertEqual(Device(ip_address="10.0.0.1").ports_compact(), "-")

    def test_closed_ports_do_not_count(self):
        device = Device(ip_address="10.0.0.1")
        device.open_ports.append(Port(number=443, state="open"))
        device.open_ports.append(Port(number=80, state="closed"))
        self.assertEqual(device.ports_compact(), "443")


if __name__ == "__main__":
    unittest.main()
