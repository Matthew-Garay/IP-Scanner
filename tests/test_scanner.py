"""Engine regressions: port scanner concurrency and VPN ranges."""

import inspect
import ipaddress
import unittest

from ip_inspector.core import network
from ip_inspector.core.models import SCAN_PORTS, ScanRequest
from ip_inspector.core.network import NetworkScanner
from ip_inspector.core.utils import (
    MAX_TARGETS,
    _is_sweepable,
    clamp_to_sweep,
    is_ip_in_virtual_subnet,
    plan_targets,
)


class PortScanConcurrency(unittest.TestCase):
    """
    The scanner used to create one task per host, each walking its ports in
    series. A single worker can only hold one semaphore permit, so the
    concurrency was decorative: a host spent a full timeout per closed port.
    With 1024 ports that was ~20 minutes per machine.

    The second version used asyncio with one task per pair, which doubled the
    time: ``connect`` releases the GIL, so a thread pool beats the event loop
    for this load. Measured here: 481 probes/s with asyncio versus 4485 with
    threads.
    """

    def test_one_probe_per_host_port_pair(self):
        source = inspect.getsource(NetworkScanner._scan_ports_threaded)
        # The serial version iterated ports INSIDE a per-host worker; now the
        # iteration queues one pair per job.
        self.assertIn("for port in request.ports", source)
        self.assertNotIn("for port_number in request.ports", source)

    def test_uses_threads_not_asyncio(self):
        source = inspect.getsource(NetworkScanner._scan_ports_threaded)
        self.assertIn("ThreadPoolExecutor", source)
        self.assertNotIn("asyncio", source)

    def test_progress_does_not_flood_the_queue(self):
        """One event per port would flood the queue the interface drains."""
        source = inspect.getsource(NetworkScanner._scan_ports_threaded)
        self.assertIn("completed % 100", source)

    def test_worker_cap_never_exceeds_the_real_probes(self):
        """Opening 2000 threads for 300 probes wastes memory for nothing."""
        source = inspect.getsource(NetworkScanner._scan_ports_threaded)
        self.assertIn("min(request.concurrency, total)", source)

    def test_defaults_are_the_fast_ones(self):
        """Regression: 1.0 s and 500 probes was the slow configuration."""
        request = ScanRequest(target_range="10.0.0.0/24")
        self.assertLessEqual(request.port_timeout, 0.5)
        self.assertGreaterEqual(request.concurrency, 2000)


class ScanPorts(unittest.TestCase):
    """The port range swept by default."""

    def test_full_range(self):
        self.assertEqual(len(SCAN_PORTS), 1024)
        self.assertEqual((SCAN_PORTS[0], SCAN_PORTS[-1]), (1, 1024))

    def test_scan_request_uses_the_full_range(self):
        request = ScanRequest(target_range="10.0.0.0/24")
        self.assertEqual(len(request.ports), 1024)
        self.assertTrue(request.scan_ports_enabled)


class VpnSweeping(unittest.TestCase):
    """
    The filter required RFC 1918, so a VPN with a public range (this machine
    advertises 26.0.0.0/8) was dropped entirely: picking the VPN adapter
    still swept the LAN behind it.
    """

    def test_public_vpn_is_sweepable(self):
        self.assertTrue(_is_sweepable(ipaddress.ip_network("26.0.0.0/8")))
        self.assertTrue(_is_sweepable(ipaddress.ip_network("100.64.0.0/10")))

    def test_what_must_not_be_swept(self):
        self.assertFalse(_is_sweepable(ipaddress.ip_network("169.254.0.0/16")))
        self.assertFalse(_is_sweepable(ipaddress.ip_network("127.0.0.0/8")))

    def test_a_slash_eight_is_clamped(self):
        """A /8 is 16 million addresses: it cannot be swept."""
        clamped = ipaddress.ip_network(
            clamp_to_sweep(ipaddress.ip_network("26.0.0.0/8")))
        self.assertLessEqual(clamped.num_addresses, MAX_TARGETS)
        self.assertGreater(clamped.num_addresses, 1)

    def test_a_normal_range_is_untouched(self):
        lan = ipaddress.ip_network("192.168.30.0/23")
        self.assertEqual(clamp_to_sweep(lan), str(lan))

    def test_the_planner_accepts_the_vpn(self):
        plan = plan_targets(clamp_to_sweep(ipaddress.ip_network("26.0.0.0/8")))
        self.assertFalse(plan.is_empty)

    def test_scanning_does_not_require_rfc1918(self):
        source = inspect.getsource(NetworkScanner._scannable_networks)
        self.assertNotIn("is_private", source)

    def test_vpn_detection_does_not_crash(self):
        self.assertFalse(is_ip_in_virtual_subnet("not-an-ip"))


class AbsorbArpAfterProbe(unittest.TestCase):
    """
    The ARP snapshot was taken BEFORE the reachability probe, but the probe
    is exactly what makes the system resolve each host to a MAC. Those
    resolutions reach the neighbour table after the snapshot, so hosts the
    scanner touched for the first time lost their MAC and the column came out
    blank even though the system already knew it.
    """

    def setUp(self):
        self.scanner = NetworkScanner.__new__(NetworkScanner)
        self.originals = {
            "read_arp_cache": network.read_arp_cache,
            "is_elevated": network.is_elevated,
            "supports_layer2": network.supports_layer2,
        }

    def tearDown(self):
        network.read_arp_cache = self.originals["read_arp_cache"]
        network.is_elevated = self.originals["is_elevated"]
        network.supports_layer2 = self.originals["supports_layer2"]

    def _without_layer2(self, cache):
        network.is_elevated = lambda: False
        network.supports_layer2 = lambda: False
        network.read_arp_cache = lambda: dict(cache)

    def test_recovers_the_mac_the_probe_taught(self):
        # The host was missing from the snapshot, but the probe resolved it.
        self._without_layer2({"192.168.30.7": "aa:bb:cc:dd:ee:01"})
        table: dict[str, str] = {}
        reachable = {"192.168.30.7": (1.0, None)}

        NetworkScanner._absorb_arp_after_probe(self.scanner, table, reachable)

        self.assertEqual(table.get("192.168.30.7"), "aa:bb:cc:dd:ee:01")

    def test_does_not_overwrite_a_known_mac(self):
        self._without_layer2({"192.168.30.7": "aa:bb:cc:dd:ee:01"})
        table = {"192.168.30.7": "11:22:33:44:55:66"}

        NetworkScanner._absorb_arp_after_probe(
            self.scanner, table, {"192.168.30.7": (1.0, None)})

        self.assertEqual(table["192.168.30.7"], "11:22:33:44:55:66")

    def test_no_entry_stays_without_mac(self):
        # A host ARP cannot reach keeps no MAC; that is correct.
        self._without_layer2({})
        table: dict[str, str] = {}

        NetworkScanner._absorb_arp_after_probe(
            self.scanner, table, {"192.168.30.7": (1.0, None)})

        self.assertEqual(table, {})

    def test_with_layer2_the_table_is_not_reread(self):
        # With layer 2 the ARP sweep already answered for everyone.
        network.is_elevated = lambda: True
        network.supports_layer2 = lambda: True
        calls = []

        def cache():
            calls.append(1)
            return {"192.168.30.7": "aa:bb:cc:dd:ee:01"}

        network.read_arp_cache = cache
        table: dict[str, str] = {}

        NetworkScanner._absorb_arp_after_probe(
            self.scanner, table, {"192.168.30.7": (1.0, None)})

        self.assertEqual(table, {})
        self.assertEqual(calls, [])

    def test_the_table_is_read_once(self):
        """Re-reading per host would enumerate every interface 200 times."""
        self._without_layer2({})
        calls = []

        def cache():
            calls.append(1)
            return {}

        network.read_arp_cache = cache
        reachable = {"192.168.30.%d" % n: (1.0, None) for n in range(2, 60)}

        NetworkScanner._absorb_arp_after_probe(
            self.scanner, {}, reachable)

        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()