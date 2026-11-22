# IP Inspector Architecture

IP Inspector is a desktop network scanner for Windows with a `customtkinter`
interface. It runs fully offline and never sends data to any server.

## Layers

```
ip_inspector/
  core/        Domain models and the scanning engine (no UI, usable headless)
  analysis/    What the findings mean: exposure, risk score, TLS/HTTP audit, reports
  actions/     Things you can do to a device: export, open RDP/web, Wake-on-LAN
  nettools/    Diagnostics (tools.py), continuous monitor, scan profiles
  interface/   Everything that touches tkinter
  i18n.py      Text catalogue (device types, findings); the app runs in English
  main.py      Development entry point (python -m ip_inspector.main)
  cli.py       Command-line scanner (headless: no tkinter import)
  __main__.py  python -m ip_inspector: the window, or the CLI when given arguments
  launcher.py  PyInstaller entry point
tests/         Regression tests (standard library only)
```

Each layer may only import from the layers listed above it
(`core` ← `analysis` ← `actions` ← `nettools` ← `interface`). `core` never
imports `interface`, which is what lets the engine run without a display.

## Scan flow

1. The Scanner tab turns the range, profile and options into a
   `ScanRequest` (`nettools/profiles.py: ScanProfile.to_request`).
2. A worker thread runs `NetworkScanner.scan()` (`core/network.py`):
   ARP sweep (or the OS ARP cache when not elevated) → reachability probe →
   vendor and hostname enrichment → threaded TCP port scan → OS fingerprint
   and classification → model identification.
3. Every step posts a `ScannerEvent` on a `queue.Queue`. The phases are
   `Discovery`, `Ports`, `Models`, `Fingerprint`, `Device`, `Finished`,
   `Cancelled` and `Error`.
4. When the engine returns, the worker scores each device with
   `analysis/exposure.py` (offline heuristics, no extra traffic) and always
   posts a final `WORKER_DONE` event, even if the engine raised.
5. The UI thread drains the queue every 100 ms and updates rows in place.

`tests/test_ui.py` pins the phase names so the window and the engine can
never drift apart again (that mismatch once kept every result off screen).

## Interface modules

| Module | Responsibility |
|--------|----------------|
| `interface/ui.py` | Main window, menu bar, Scanner and Favorites tabs, scan lifecycle, context menu |
| `interface/widgets.py` | `DeviceTree` (results table) and `DetailPanel` |
| `interface/tools_tab.py` | Tools tab; every tool is one entry in the `TOOLS` table |
| `interface/monitor_tab.py` | Monitor tab on top of `nettools/monitor.py` |
| `interface/settings.py` | Preferences, favorites and known devices in `~/.ip_inspector/settings.json` |
| `interface/theme.py` | Light and dark palettes |

## Adding a tool

Write a function in `nettools/tools.py` that returns a `ToolResult` (never
raise; set `ok=False` and `error` instead), then add one `Tool(...)` entry to
`TOOLS` in `interface/tools_tab.py`. The form, the worker thread and the
console output are built from that entry.

## Port scan details

The port sweep runs one thread-pool job per (host, port) pair. Live hosts
where *every* probe timed out get a second pass with double the timeout
(`NetworkScanner._retry_silent_hosts`, port lists up to 256): on Wi-Fi a
momentary stall otherwise hid a router's open ports under the 0.4 s Quick
timeout.

## Persistent state

`interface/settings.py` stores, per user: scan options, favorites, the
devices ever seen (NEW flags), the previous complete scan of a range (to
list what is *gone*), custom device names/notes and the auto-rescan
interval. Devices are keyed by MAC, or by IP when the MAC is unknown, so a
name survives a DHCP address change.

## Adding a scan profile

Add a `ScanProfile` to `nettools/profiles.py` and list it in `PROFILES`. The
profile menu, the options row and the request builder pick it up
automatically.
