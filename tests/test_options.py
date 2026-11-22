"""Scan profiles, port parsing, settings persistence and the tools catalogue.

Pure logic: no window and no network traffic.
"""

import json
import tempfile
import unittest
from pathlib import Path

from ip_inspector.nettools import profiles
from ip_inspector.nettools.profiles import PROFILES, get_profile, parse_ports


class PortParsing(unittest.TestCase):

    def test_lists_ranges_and_spaces(self):
        self.assertEqual(parse_ports("22, 80 443,8000-8002"), (22, 80, 443, 8000, 8001, 8002))

    def test_reversed_range_and_duplicates(self):
        self.assertEqual(parse_ports("90-88,89"), (88, 89, 90))

    def test_full_range(self):
        self.assertEqual(len(parse_ports("1-65535")), 65535)

    def test_rejects_bad_input(self):
        for text in ("", "abc", "0", "70000", "10-x"):
            with self.assertRaises(ValueError, msg=text):
                parse_ports(text)


class Profiles(unittest.TestCase):

    def test_keys_are_unique(self):
        keys = [p.key for p in PROFILES]
        self.assertEqual(len(keys), len(set(keys)))

    def test_lookup_by_key_and_name(self):
        self.assertIs(get_profile("full"), profiles.FULL)
        self.assertIs(get_profile("Full (1-1024)"), profiles.FULL)
        self.assertIs(get_profile("missing"), profiles.STANDARD)

    def test_to_request_applies_overrides(self):
        request = profiles.QUICK.to_request("10.0.0.0/24", port_timeout=2.0)
        self.assertEqual(request.ports, profiles.QUICK_PORTS)
        self.assertEqual(request.port_timeout, 2.0)
        self.assertEqual(request.profile, "quick")

    def test_discovery_does_not_scan_ports(self):
        self.assertFalse(profiles.DISCOVERY.to_request("10.0.0.1").scan_ports_enabled)

    def test_ports_are_valid(self):
        for profile in PROFILES:
            for port in profile.ports:
                self.assertTrue(1 <= port <= 65535, (profile.key, port))


class SettingsFile(unittest.TestCase):

    def test_round_trip_and_bad_files(self):
        try:
            from ip_inspector.interface.settings import Settings
        except Exception as exc:  # pragma: no cover - no tkinter
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "settings.json"
            Settings(profile="full", favorites=["10.0.0.1"], timeout=1.0).save(path)
            loaded = Settings.load(path)
            self.assertEqual((loaded.profile, loaded.favorites, loaded.timeout),
                             ("full", ["10.0.0.1"], 1.0))
            path.write_text("{not json", encoding="utf-8")
            self.assertEqual(Settings.load(path).profile, "standard")
            path.write_text(json.dumps({"threads": "lots", "profile": "iot"}), encoding="utf-8")
            loaded = Settings.load(path)
            self.assertEqual((loaded.threads, loaded.profile), (1000, "iot"))


class ToolsCatalogue(unittest.TestCase):

    def setUp(self):
        try:
            from ip_inspector.interface import tools_tab
        except Exception as exc:  # pragma: no cover - no tkinter
            self.skipTest(str(exc))
        self.tools_tab = tools_tab

    def test_names_are_unique_and_resolvable(self):
        names = [tool.name for tool in self.tools_tab.TOOLS]
        self.assertEqual(len(names), len(set(names)))
        for name in names:
            self.assertEqual(self.tools_tab.get_tool(name).name, name)

    def test_offline_tools_run(self):
        """Tools that need no network must return a result, not raise."""
        cases = {
            "Subnet calculator": {"cidr": "192.168.1.0/24"},
            "Subnet split": {"cidr": "10.0.0.0/24", "count": "4"},
            "IP in network?": {"ip": "10.0.0.5", "cidr": "10.0.0.0/24"},
        }
        for name, values in cases.items():
            result = self.tools_tab.get_tool(name).run(values)
            self.assertTrue(result.ok, (name, result.error))
            self.assertTrue(result.output or result.lines, name)
        self.assertIn("Usable", self.tools_tab.get_tool("Subnet calculator")
                      .run(cases["Subnet calculator"]).output)

    def test_port_check_reports_bad_ports_as_an_error(self):
        with self.assertRaises(ValueError):
            self.tools_tab.get_tool("Port check").run({"host": "127.0.0.1", "ports": "x"})


class BannerCleaning(unittest.TestCase):

    def test_binary_greeting_becomes_readable_text(self):
        """The port sweep used to show MySQL's raw bytes ('E\\x00\\x00\\x00\\xffj\\x04Host…')."""
        import socket
        import threading

        from ip_inspector.core.network import NetworkScanner

        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def greet():
            conn, _ = server.accept()
            conn.sendall(b"E\x00\x00\x00\xffj\x04Host 'pc' is not allowed to connect")
            conn.close()

        thread = threading.Thread(target=greet, daemon=True)
        thread.start()
        try:
            result = NetworkScanner()._probe_port_sync("127.0.0.1", port, 1.0)
        finally:
            thread.join(2)
            server.close()
        self.assertTrue(result.is_open)
        self.assertIn("Host 'pc' is not allowed", result.banner)
        self.assertTrue(all(ch.isprintable() for ch in result.banner), repr(result.banner))


if __name__ == "__main__":
    unittest.main()
