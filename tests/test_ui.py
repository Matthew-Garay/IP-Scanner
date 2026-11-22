"""Regression tests for the main window.

The bug that started this file: the window listened for event phases the
engine never emits ("device", "done") instead of the real ones ("Device",
"Finished"). The scan finished fine, but no device ever reached the table and
the Scan button stayed disabled forever.

The engine is replaced by events pushed straight onto the queue, exactly as
``NetworkScanner`` emits them, so no network traffic is involved. Settings
are redirected to a temporary folder so the user's own file is never touched.
"""

import tempfile
import unittest
from pathlib import Path

from ip_scanner.core.models import Device, Port, ScannerEvent

try:
    from ip_scanner.interface import settings as settings_module
    from ip_scanner.interface import ui
    from ip_scanner.interface.settings import Settings
    from ip_scanner.interface.widgets import COL_PORTS
    _GUI = True
except Exception:  # pragma: no cover - no tkinter, no interface
    _GUI = False


def _device(ip, hostname="", ports=(), vendor="", mac="AA:BB:CC:00:00:01"):
    return Device(
        ip_address=ip, hostname=hostname, vendor=vendor, mac_address=mac,
        open_ports=[Port(number, "open", "http" if number == 80 else "") for number in ports]
        + [Port(9999, "closed")],
    )


@unittest.skipUnless(_GUI, "the interface needs tkinter")
class WindowTestCase(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._saved_path = settings_module.SETTINGS_FILE
        settings_module.SETTINGS_FILE = Path(self._tmp.name) / "settings.json"
        try:
            self.app = ui.ScannerApp(settings=Settings(last_range="10.0.0.0/24"))
        except Exception as exc:  # pragma: no cover - CI without a display
            settings_module.SETTINGS_FILE = self._saved_path
            self._tmp.cleanup()
            self.skipTest(f"no display: {exc}")
        self.app.withdraw()

    def tearDown(self):
        try:
            self.app.destroy()
        except Exception:
            pass
        settings_module.SETTINGS_FILE = self._saved_path
        self._tmp.cleanup()

    def _pump(self, *events):
        for event in events:
            self.app._events.put(event)
        self.app._poll_queue()
        self.app.update_idletasks()

    def _finish(self, *devices):
        self.app._scanning = True
        self.app._set_buttons(scanning=True)
        self._pump(*(ScannerEvent("Device", device=d) for d in devices),
                   ScannerEvent("Finished", f"{len(devices)} devices found"),
                   ScannerEvent(ui.WORKER_DONE))


class EventContract(WindowTestCase):

    def test_phases_match_the_engine(self):
        """The constants must be the strings core/network.py emits."""
        import inspect
        from ip_scanner.core import network
        source = inspect.getsource(network)
        for phase in (ui.PHASE_DEVICE, ui.PHASE_FINISHED, ui.PHASE_CANCELLED,
                      ui.PHASE_ERROR, *ui.PROGRESS_PHASES):
            self.assertIn(f'ScannerEvent("{phase}"', source, phase)

    def test_devices_reach_the_table_and_the_scan_finishes(self):
        self.app._scanning = True
        self.app._set_buttons(scanning=True)
        self._pump(
            ScannerEvent("Discovery", "Scanning 254 addresses", 0, 254),
            ScannerEvent("Device", device=_device("192.168.1.10", "pc", (80, 445))),
            ScannerEvent("Device", device=_device("192.168.1.2", "router", (53,))),
            ScannerEvent("Ports", "", 50, 100),
            ScannerEvent("Finished", "2 devices found"),
            ScannerEvent(ui.WORKER_DONE),
        )
        self.assertEqual(self.app._tree.row_count(), 2)
        self.assertFalse(self.app._scanning)
        self.assertEqual(str(self.app._scan_btn.cget("state")), "normal")
        self.assertEqual(str(self.app._stop_btn.cget("state")), "disabled")
        self.assertIn("Scan finished", self.app._status_label.cget("text"))

    def test_stop_keeps_scan_disabled_until_the_worker_exits(self):
        """Stop used to re-enable Scan while the old scan was still running."""
        self.app._scanning = True
        self.app._set_buttons(scanning=True)
        self.app._on_stop_click()
        self.assertTrue(self.app._stop_event.is_set())
        self.assertEqual(str(self.app._scan_btn.cget("state")), "disabled")
        self._pump(ScannerEvent("Cancelled", "Scan stopped by user"),
                   ScannerEvent(ui.WORKER_DONE))
        self.assertEqual(str(self.app._scan_btn.cget("state")), "normal")
        self.assertIn("Scan stopped", self.app._status_label.cget("text"))

    def test_an_engine_crash_still_releases_the_buttons(self):
        self.app._scanning = True
        self.app._set_buttons(scanning=True)
        self.app._handle_event(ScannerEvent(ui.WORKER_DONE))
        self.assertEqual(str(self.app._scan_btn.cget("state")), "normal")


class Table(WindowTestCase):

    def test_rows_sort_by_numeric_ip(self):
        self._pump(*(ScannerEvent("Device", device=_device(ip))
                     for ip in ("10.0.0.20", "10.0.0.3", "10.0.0.100")))
        self.assertEqual(self.app._tree.visible_ips(), ["10.0.0.3", "10.0.0.20", "10.0.0.100"])

    def test_updating_a_device_keeps_the_selection(self):
        self._pump(ScannerEvent("Device", device=_device("10.0.0.1")),
                   ScannerEvent("Device", device=_device("10.0.0.2")))
        self.app._tree.select("10.0.0.2")
        self._pump(ScannerEvent("Device", device=_device("10.0.0.2", "new-name", (22,))))
        self.assertEqual(self.app._tree.get_selected_ip(), "10.0.0.2")
        self.assertEqual(self.app._tree.row_values("10.0.0.2")[0], "new-name")
        self.assertEqual(self.app._tree.row_values("10.0.0.2")[COL_PORTS], "22")

    def test_only_open_ports_become_service_rows(self):
        self._pump(ScannerEvent("Device", device=_device("10.0.0.1", ports=(80, 443))))
        self.assertEqual(len(self.app._tree._tree.get_children("dev:10.0.0.1")), 2)

    def test_filter_hides_and_restores_rows(self):
        self._pump(ScannerEvent("Device", device=_device("10.0.0.1", "printer")),
                   ScannerEvent("Device", device=_device("10.0.0.2", "laptop")))
        self.app._tree.set_filter("print")
        self.assertEqual(self.app._tree.row_count(), 1)
        self.app._tree.set_filter("")
        self.assertEqual(self.app._tree.row_count(), 2)

    def test_only_open_hides_silent_hosts(self):
        self._pump(ScannerEvent("Device", device=_device("10.0.0.1", ports=(22,))),
                   ScannerEvent("Device", device=_device("10.0.0.2")))
        self.app._tree.set_filter("", only_open=True)
        self.assertEqual(self.app._tree.visible_ips(), ["10.0.0.1"])

    def test_headings_are_english_text(self):
        for i, (label, *_rest) in enumerate(ui.TREE_COLUMNS):
            heading = self.app._tree._tree.heading(f"c{i}", "text")
            self.assertTrue(heading.startswith(label))
            self.assertNotIn("col.", heading.lower())


class NewDevices(WindowTestCase):

    def test_first_scan_is_the_baseline_and_later_newcomers_are_flagged(self):
        self._finish(_device("10.0.0.1", mac="AA:00:00:00:00:01"))
        self.assertEqual(self.app._new_devices, set())
        self.app._start_scan = lambda *a, **k: None   # keep the table, no thread
        self._finish(_device("10.0.0.1", mac="AA:00:00:00:00:01"),
                     _device("10.0.0.9", mac="AA:00:00:00:00:09"))
        self.assertEqual(self.app._new_devices, {"10.0.0.9"})
        self.assertIn("new", self.app._summary_label.cget("text"))


class Changes(WindowTestCase):

    def test_devices_missing_from_the_previous_scan_are_reported_gone(self):
        self.app._last_range = "10.0.0.0/24"
        self._finish(_device("10.0.0.1", mac="AA:00:00:00:00:01"),
                     _device("10.0.0.2", mac="AA:00:00:00:00:02"))
        self.assertEqual(self.app._gone, [])
        self.app._devices.clear()
        self._finish(_device("10.0.0.1", mac="AA:00:00:00:00:01"))
        self.assertEqual([g["ip"] for g in self.app._gone], ["10.0.0.2"])
        self.assertIn("1 no longer answering", self.app._summary_label.cget("text"))

    def test_a_different_range_is_not_compared(self):
        self.app._last_range = "10.0.0.0/24"
        self._finish(_device("10.0.0.1", mac="AA:00:00:00:00:01"))
        self.app._devices.clear()
        self.app._last_range = "10.0.1.0/24"
        self._finish(_device("10.0.1.5", mac="AA:00:00:00:00:05"))
        self.assertEqual(self.app._gone, [])


class Labels(WindowTestCase):

    def test_custom_name_shows_in_the_table_and_persists(self):
        self._pump(ScannerEvent("Device", device=_device("10.0.0.3", "dlink-cam",
                                                         mac="AA:00:00:00:00:03")))
        self.app.set_label("10.0.0.3", "Garage camera", "check firmware")
        self.assertEqual(self.app._tree.row_values("10.0.0.3")[0], "Garage camera")
        saved = Settings.load().device_labels["AA:00:00:00:00:03"]
        self.assertEqual(saved, {"name": "Garage camera", "note": "check firmware"})
        self.app._tree.set_filter("garage")
        self.assertEqual(self.app._tree.row_count(), 1)

    def test_the_name_follows_the_mac_to_a_new_ip(self):
        self.app.settings.device_labels["AA:00:00:00:00:04"] = {"name": "Printer", "note": ""}
        self._pump(ScannerEvent("Device", device=_device("10.0.0.44", mac="AA:00:00:00:00:04")))
        self.assertEqual(self.app._tree.row_values("10.0.0.44")[0], "Printer")

    def test_clearing_both_fields_removes_the_label(self):
        self._pump(ScannerEvent("Device", device=_device("10.0.0.3", "cam")))
        self.app.set_label("10.0.0.3", "Cam")
        self.app.set_label("10.0.0.3", "", "")
        self.assertEqual(self.app._tree.row_values("10.0.0.3")[0], "cam")
        self.assertEqual(Settings.load().device_labels, {})


class AutoRescan(WindowTestCase):

    def test_a_complete_scan_schedules_the_next_one(self):
        self.app._auto_menu.set("15 min")
        self._finish(_device("10.0.0.1"))
        self.assertIsNotNone(self.app._auto_job)
        self.assertIn("next scan at", self.app._status_label.cget("text"))

    def test_off_cancels_the_pending_scan(self):
        self.app._auto_menu.set("15 min")
        self._finish(_device("10.0.0.1"))
        self.app._auto_menu.set("Off")
        self.app._on_auto_change()
        self.assertIsNone(self.app._auto_job)
        self.assertEqual(Settings.load().auto_rescan, 0)


class AutomaticRange(WindowTestCase):
    """The range follows this computer's network until the user types one."""

    def setUp(self):
        super().setUp()
        self.app._range_is_auto = True
        self.app._detected_range = ""

    def test_detected_network_fills_the_range(self):
        self.app._on_network_detected("192.168.7.0/24")
        self.assertEqual(self.app._range_entry.get(), "192.168.7.0/24")
        self.assertIn("detected", self.app._range_info.cget("text"))

    def test_moving_to_another_network_updates_the_range(self):
        self.app._on_network_detected("192.168.7.0/24")
        self.app._on_network_detected("10.20.0.0/24")
        self.assertEqual(self.app._range_entry.get(), "10.20.0.0/24")
        self.assertIn("Network changed", self.app._status_label.cget("text"))

    def test_a_typed_range_is_never_overwritten(self):
        self.app._on_network_detected("192.168.7.0/24")
        self.app._range_entry.set("10.9.9.0/24")
        self.app._on_range_typed()
        self.app._on_network_detected("10.20.0.0/24")
        self.assertEqual(self.app._range_entry.get(), "10.9.9.0/24")

    def test_typing_the_detected_range_back_resumes_auto_mode(self):
        self.app._on_network_detected("192.168.7.0/24")
        self.app._range_entry.set("10.9.9.0/24")
        self.app._on_range_typed()
        self.app._range_entry.set("192.168.7.0/24")
        self.app._on_range_typed()
        self.app._on_network_detected("10.20.0.0/24")
        self.assertEqual(self.app._range_entry.get(), "10.20.0.0/24")

    def test_no_change_while_scanning(self):
        self.app._on_network_detected("192.168.7.0/24")
        self.app._scanning = True
        self.app._on_network_detected("10.20.0.0/24")
        self.assertEqual(self.app._range_entry.get(), "192.168.7.0/24")
        self.app._scanning = False


class Options(WindowTestCase):

    def test_custom_profile_builds_a_request_with_typed_ports(self):
        self.app._profile_menu.set("Custom ports")
        self.app._on_profile_change()
        self.app._ports_entry.delete(0, "end")
        self.app._ports_entry.insert(0, "22, 80, 8000-8002")
        request = self.app._build_request("10.0.0.1")
        self.assertEqual(request.ports, (22, 80, 8000, 8001, 8002))
        self.assertTrue(request.scan_ports_enabled)

    def test_ping_sweep_profile_skips_ports(self):
        self.app._profile_menu.set("Ping sweep only")
        self.app._on_profile_change()
        request = self.app._build_request("10.0.0.0/24")
        self.assertFalse(request.scan_ports_enabled)

    def test_favorites_persist(self):
        self._pump(ScannerEvent("Device", device=_device("10.0.0.7")))
        self.app._toggle_favorite("10.0.0.7")
        self.assertEqual(Settings.load().favorites, ["10.0.0.7"])
        self.assertEqual(len(self.app._favs_list.get_children()), 1)


class NativeWindow(WindowTestCase):
    """The window is plain Tk/ttk now: no customtkinter, native theme."""

    def test_no_customtkinter_anywhere(self):
        import sys as _sys
        self.assertNotIn("customtkinter", _sys.modules)
        self.assertIsInstance(self.app, __import__("tkinter").Tk)

    def test_property_grid_shows_the_selected_device(self):
        self._pump(ScannerEvent("Device", device=_device("10.0.0.5", "nas", (445,),
                                                         vendor="Synology")))
        self.app._tree.select("10.0.0.5")
        self.app._on_device_selected("10.0.0.5")
        self.assertEqual(self.app._detail.value_of("Manufacturer"), "Synology")
        self.assertEqual(self.app._detail.value_of("IP address"), "10.0.0.5")

    def test_properties_panel_can_be_hidden_and_restored(self):
        self.app._toggle_detail()
        self.assertNotIn(str(self.app._detail), self.app._paned.panes())
        self.app._toggle_detail()
        self.assertIn(str(self.app._detail), self.app._paned.panes())

    def test_shares_appear_under_the_device(self):
        self._pump(ScannerEvent("Device", device=_device("10.0.0.5", ports=(445,))))
        self.app._show_shares("10.0.0.5", [("Public", "Disk", ""), ("Scans", "Disk", "")], "")
        children = self.app._tree._tree.get_children("dev:10.0.0.5")
        self.assertIn("share:10.0.0.5:Public", children)
        self.assertEqual(sum(c.startswith("svc:") for c in children), 1)
        # a later update of the device keeps its shares
        self._pump(ScannerEvent("Device", device=_device("10.0.0.5", "nas", (445,))))
        self.assertIn("share:10.0.0.5:Scans", self.app._tree._tree.get_children("dev:10.0.0.5"))

    def test_copy_selected_rows_as_tab_separated_text(self):
        self._pump(ScannerEvent("Device", device=_device("10.0.0.1", "a")),
                   ScannerEvent("Device", device=_device("10.0.0.2", "b")))
        self.app._select_all()
        self.app._copy_selected()
        lines = self.app.clipboard_get().splitlines()
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[0].startswith("Name\tIP"))
        self.assertEqual(self.app._tree.get_selected_ips(), ["10.0.0.1", "10.0.0.2"])

    def test_bulk_context_menu_for_several_devices(self):
        self._pump(ScannerEvent("Device", device=_device("10.0.0.1")),
                   ScannerEvent("Device", device=_device("10.0.0.2")))
        menu = __import__("tkinter").Menu(self.app, tearoff=0)
        self.app._fill_device_menu(menu, ["10.0.0.1", "10.0.0.2"])
        labels = [menu.entrycget(i, "label") for i in range(menu.index("end") + 1)
                  if menu.type(i) != "separator"]
        self.assertIn("Rescan 2 devices", labels)
        self.assertIn("Copy 2 rows", labels)

    def test_single_device_menu_disables_what_does_not_apply(self):
        self._pump(ScannerEvent("Device", device=_device("10.0.0.1", ports=(22,))))
        menu = __import__("tkinter").Menu(self.app, tearoff=0)
        self.app._fill_device_menu(menu, ["10.0.0.1"])
        open_with = self.app.nametowidget(menu.entrycget("Open with", "menu"))
        self.assertEqual(str(open_with.entrycget("SSH", "state")), "normal")
        self.assertEqual(str(open_with.entrycget("Remote Desktop (RDP)", "state")), "disabled")

    def test_saved_results_can_be_reopened(self):
        from ip_scanner.actions.exporter import export_json
        path = Path(self._tmp.name) / "results.json"
        export_json([_device("10.0.0.8", "printer", (9100,))], path,
                    {"range": "10.0.0.0/24"})
        self.assertTrue(self.app.load_results(str(path)))
        self.assertEqual(self.app._tree.visible_ips(), ["10.0.0.8"])
        self.assertEqual(self.app._range_entry.get(), "10.0.0.0/24")

    def test_range_history_is_remembered(self):
        self.app._range_entry.set("10.9.0.0/24")
        self.app._save_options()
        self.assertEqual(Settings.load().range_history[0], "10.9.0.0/24")
        self.assertIn("10.9.0.0/24", self.app._range_entry.cget("values"))


@unittest.skipUnless(_GUI, "the interface needs tkinter")
class PureHelpers(unittest.TestCase):

    def test_device_row_has_one_cell_per_column(self):
        self.assertEqual(len(ui.device_row(_device("10.0.0.1"))), len(ui.TREE_COLUMNS))

    def test_filter_searches_vendor_and_ports(self):
        device = _device("10.0.0.1", vendor="Hikvision", ports=(554,))
        self.assertTrue(ui.matches_filter(device, "hikv"))
        self.assertTrue(ui.matches_filter(device, "554"))
        self.assertFalse(ui.matches_filter(device, "cisco"))


if __name__ == "__main__":
    unittest.main()
