# WeftScan Architecture

WeftScan is a desktop network scanner for Windows with a Tkinter/ttk
interface that uses the native Windows controls (the `vista` ttk theme). It runs fully offline and never sends data to any server.

## Layers

```
weftscan/
  core/        Domain models and the scanning engine (no UI, usable headless)
               discovery.py: SSDP/UPnP and mDNS listening; devicetype.py: categories
  analysis/    What the findings mean: exposure, risk score, TLS/HTTP audit, reports
  actions/     Things you can do to a device: export, open RDP/web, Wake-on-LAN
  nettools/    Diagnostics (tools.py), continuous monitor, scan profiles
  interface/   Everything that touches tkinter
  i18n.py      Text catalogue (device types, findings); the app runs in English
  main.py      Development entry point (python -m weftscan.main)
  cli.py       Command-line scanner (headless: no tkinter import)
  __main__.py  python -m weftscan: the window, or the CLI when given arguments
  launcher.py  PyInstaller entry point
tests/         Regression tests (standard library only)
tools/         Design-time scripts: make_icons.py (icon set, needs Pillow),
               make_sample.py (docs/sample-results.json)
```

Each layer may only import from the layers listed above it
(`core` ← `analysis` ← `actions` ← `nettools` ← `interface`). `core` never
imports `interface`, which is what lets the engine run without a display.

## Scan flow

1. The Scanner tab turns the range, profile and options into a
   `ScanRequest` (`nettools/profiles.py: ScanProfile.to_request`).
2. A worker thread runs `NetworkScanner.scan()` (`core/network.py`):
   ARP sweep (or the OS ARP cache when not elevated) and, in parallel, SSDP/mDNS
   listening (`core/discovery.py`) → reachability probe →
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
| `interface/widgets.py` | `DeviceTree` (results grid), `AddressMap`, `DetailsPanel`, `ViewStack` (navigation rail) |
| `interface/tools_tab.py` | Tools tab; every tool is one entry in the `TOOLS` table |
| `interface/monitor_tab.py` | Monitor tab on top of `nettools/monitor.py` |
| `interface/settings.py` | Preferences, favorites and known devices in `~/.weftscan/settings.json` |
| `interface/theme.py` | Colour tokens, flat ttk styles on `clam`, DPI scaling (`px`) and the icon loader |

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

## Device categories

`core/devicetype.categorize()` decides what a device is, using evidence in
order of trust:

1. this computer / the default gateway;
2. what the device announced: UPnP device types and mDNS services;
3. its announced model or friendly name;
4. its host name;
5. ports that name a single job (printing, RTSP, Cast);
6. its MAC vendor, a randomized (private) MAC, then the engine fingerprint.

Each category key matches an icon in `assets/icons/<key>_<size>.png`.
`tests/test_devicetype.py` checks every category has one.

## Visual design

The identity comes from the name: the *weft* is the thread that runs across
a loom. Its one memorable element is **the weave**, the address map drawn as
a woven strip (one stitch per address, the thread passing over every other
empty one, raised stitches for devices that answered). Everything around it
stays quiet: white work surfaces on cool "loom steel" chrome (`#EEF0F4`),
indigo-black ink (`#1B2033`) and one **indigo** accent (`#2B3F96`) for the
primary action, the current view, selection and the weave, where devices
that answered are indigo stitches. Status colours are natural dyes and appear
only on the row badges and the weave: verdigris (online badge), weld (needs
attention), madder (critical); new devices are ink.
Bahnschrift, shipped with Windows, sets the wordmark and titles;
Segoe UI sets everything you read. The app mark is a small piece of weave
with one loose weld thread. Icons are outline glyphs on a 64-unit grid drawn
by `tools/make_icons.py`.
