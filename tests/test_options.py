"""Scan profiles, port parsing, settings persistence and the tools catalogue.

Pure logic: no window and no network traffic.
"""

import json
import tempfile
import unittest
from pathlib import Path

from ip_scanner.nettools import profiles
from ip_scanner.nettools.profiles import PROFILES, get_profile, parse_ports


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
            from ip_scanner.interface.settings import Settings
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
            from ip_scanner.interface import tools_tab
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


class SharesAndPower(unittest.TestCase):

    SPANISH = (
        "Recursos compartidos en \\\\192.168.1.74\n\nEquipo3\n\n"
        "Nombre de recurso compartido  Tipo   Usado como  Comentario     \n\n"
        "-------------------------------------------------------------------------------\n"
        "ADMIN$                        Disco              Remote Admin   \n"
        "Public Files                  Disco                             \n"
        "IPC$                          IPC                Remote IPC     \n"
        "Se ha completado el comando correctamente.\n"
    )
    ENGLISH = (
        "Shared resources at \\\\NAS\n\n\n\n"
        "Share name  Type  Used as  Comment\n\n"
        "-------------------------------------------------------------------------------\n"
        "media       Disk           Movies and music\n"
        "printer     Print          Office laser\n"
        "The command completed successfully.\n"
    )

    def test_net_view_is_parsed_in_any_language(self):
        from ip_scanner.nettools.tools import parse_net_view
        self.assertEqual(parse_net_view(self.SPANISH), [
            ("ADMIN$", "Disco", "Remote Admin"), ("Public Files", "Disco", ""),
            ("IPC$", "IPC", "Remote IPC")])
        self.assertEqual(parse_net_view(self.ENGLISH), [
            ("media", "Disk", "Movies and music"), ("printer", "Print", "Office laser")])

    def test_net_view_without_shares(self):
        from ip_scanner.nettools.tools import parse_net_view
        self.assertEqual(parse_net_view("System error 53 has occurred.\n"), [])

    def test_remote_power_rejects_unknown_actions(self):
        from ip_scanner.actions.menu import remote_power
        ok, message = remote_power("10.0.0.1", "explode")
        self.assertFalse(ok)

    def test_saved_json_round_trips(self):
        from ip_scanner.actions.exporter import device_to_dict, export_json, load_json
        from ip_scanner.core.models import Device, Port, SecurityFinding
        device = Device(ip_address="10.0.0.1", mac_address="aa:bb:cc:dd:ee:ff",
                        hostname="x", open_ports=[Port(80, "open", "HTTP", banner="b")],
                        risk_score=12)
        device.findings = [SecurityFinding("high", "t", "d", "10.0.0.1")]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "r.json"
            export_json([device], path, {"range": "10.0.0.0/24"})
            loaded, session = load_json(path)
            self.assertEqual(device_to_dict(loaded[0]), device_to_dict(device))
            self.assertEqual(session["range"], "10.0.0.0/24")
            path.write_text('{"something": 1}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_json(path)


class BannerCleaning(unittest.TestCase):

    def test_binary_greeting_becomes_readable_text(self):
        """The port sweep used to show MySQL's raw bytes ('E\\x00\\x00\\x00\\xffj\\x04Host…')."""
        import socket
        import threading

        from ip_scanner.core.network import NetworkScanner

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
