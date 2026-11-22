"""Command-line interface and the engine's retry of silent hosts.

The scanner is replaced by a fake that emits the same events as the real
one, so these tests send no traffic beyond localhost.
"""

import io
import json
import queue
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from ip_scanner import cli
from ip_scanner.core.models import Device, Port, ScannerEvent, ScanRequest
from ip_scanner.core.network import NetworkScanner


class FakeScanner:
    """Stands in for NetworkScanner: records the request, returns fixed devices."""

    def __init__(self, devices):
        self.event_queue = queue.Queue()
        self.devices = devices
        self.request = None

    def scan(self, request, stop_event=None):
        self.request = request
        self.event_queue.put(ScannerEvent("Discovery", "Scanning", 0, 1))
        self.event_queue.put(ScannerEvent("Ports", "", 1, 1))
        self.event_queue.put(ScannerEvent("Finished", "done"))
        return self.devices


def _devices():
    return [
        Device(ip_address="10.0.0.1", mac_address="AA:BB:CC:00:00:01", hostname="router",
               open_ports=[Port(53, "open", "DNS"), Port(80, "open", "HTTP")]),
        Device(ip_address="10.0.0.9", hostname="nas",
               open_ports=[Port(23, "open", "Telnet"), Port(445, "open", "SMB")]),
        Device(ip_address="10.0.0.20", open_ports=[Port(22, "closed")]),
    ]


class Cli(unittest.TestCase):

    def _run(self, *argv, devices=None):
        out, err = io.StringIO(), io.StringIO()
        scanner = FakeScanner(devices if devices is not None else _devices())
        code = cli.run(list(argv), out=out, err=err, scanner=scanner)
        return code, out.getvalue(), err.getvalue(), scanner

    def test_prints_a_table_and_a_summary(self):
        code, out, _err, _scanner = self._run("10.0.0.0/24", "-q")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("10.0.0.9", out)
        self.assertIn("53, 80", out)
        self.assertIn("3 device(s), 2 with open ports", out)

    def test_profile_and_options_reach_the_request(self):
        _code, _out, _err, scanner = self._run(
            "10.0.0.0/24", "-q", "-p", "quick", "-t", "1.5", "-T", "300", "--no-resolve")
        request: ScanRequest = scanner.request
        self.assertEqual(request.profile, "quick")
        self.assertEqual((request.port_timeout, request.concurrency), (1.5, 300))
        self.assertFalse(request.resolve_hostnames)

    def test_custom_ports(self):
        _code, _out, _err, scanner = self._run("10.0.0.1", "-q", "--ports", "22,8000-8002")
        self.assertEqual(scanner.request.ports, (22, 8000, 8001, 8002))
        self.assertEqual(scanner.request.profile, "custom")

    def test_only_open_hides_silent_hosts(self):
        _code, out, _err, _scanner = self._run("10.0.0.0/24", "-q", "--only-open")
        self.assertNotIn("10.0.0.20", out)

    def test_bad_input_exits_with_usage_code(self):
        for argv in (["not-a-range", "-q"], ["10.0.0.1", "--ports", "x"],
                     ["10.0.0.1", "-o", "out.txt"], ["10.0.0.1", "-T", "0"]):
            code, _out, err, _scanner = self._run(*argv)
            self.assertEqual(code, cli.EXIT_USAGE, argv)
            self.assertIn("error", err)

    def test_fail_on_risk(self):
        code, _out, err, _scanner = self._run("10.0.0.0/24", "-q", "--fail-on-risk", "30")
        self.assertEqual(code, cli.EXIT_RISK)
        self.assertIn("10.0.0.9", err)

    def test_writes_csv_and_json(self):
        with tempfile.TemporaryDirectory() as folder:
            csv_path, json_path = Path(folder, "r.csv"), Path(folder, "r.json")
            code, _out, _err, _scanner = self._run(
                "10.0.0.0/24", "-q", "-o", str(csv_path), "-o", str(json_path))
            self.assertEqual(code, cli.EXIT_OK)
            self.assertIn("10.0.0.9", csv_path.read_text(encoding="utf-8-sig"))
            data = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(data["device_count"], 3)

    def test_list_profiles(self):
        code, out, _err, _scanner = self._run("--list-profiles")
        self.assertEqual(code, cli.EXIT_OK)
        for key in ("quick", "standard", "full", "iot", "discovery", "custom"):
            self.assertIn(key, out)

    def test_table_handles_no_devices(self):
        code, out, _err, _scanner = self._run("10.0.0.0/24", "-q", devices=[])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("0 device(s)", out)


class SilentHostRetry(unittest.TestCase):
    """
    On Wi-Fi the router sometimes stalled for a moment during the 0.4 s Quick
    sweep, every probe timed out, and it was listed with no open ports while
    53 and 80 were open. Live hosts that answered nothing get a second pass.
    """

    def test_a_host_that_timed_out_everywhere_is_probed_again(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(8)
        port = server.getsockname()[1]
        accepting = threading.Event()

        def serve():
            while True:
                try:
                    conn, _ = server.accept()
                except OSError:
                    return
                conn.close()

        threading.Thread(target=serve, daemon=True).start()
        scanner = NetworkScanner()
        calls = []
        real_probe = scanner._probe_port_sync

        def flaky_probe(ip, number, timeout):
            calls.append(timeout)
            if len(calls) == 1:                 # first pass: simulated stall
                return Port(number, "filtered")
            accepting.set()
            return real_probe(ip, number, timeout)

        scanner._probe_port_sync = flaky_probe
        device = Device(ip_address="127.0.0.1")
        try:
            scanner._scan_ports_threaded(
                [device], ScanRequest("127.0.0.1", ports=(port,), port_timeout=0.4))
        finally:
            server.close()
        self.assertEqual([p.state for p in device.open_ports], ["open"])
        self.assertEqual(calls, [0.4, 0.8])

    def test_hosts_with_any_answer_are_not_retried(self):
        scanner = NetworkScanner()
        calls = []
        scanner._probe_port_sync = lambda ip, n, t: calls.append(n) or Port(n, "closed")
        scanner._scan_ports_threaded(
            [Device(ip_address="10.0.0.1")], ScanRequest("10.0.0.1", ports=(1, 2, 3)))
        self.assertEqual(len(calls), 3)


if __name__ == "__main__":
    unittest.main()
