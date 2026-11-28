# WeftScan — notes for contributors and coding agents

Windows desktop app that scans the local network: discovers devices, checks
open ports, identifies model and operating system, scores security exposure,
and bundles network diagnostics and a host monitor. The whole UI is English.

Production dependencies: `scapy`, `psutil`, `mac-vendor-lookup`. The GUI is
Tkinter/ttk from the standard library.

## Layout

```
WeftScan.spec      PyInstaller spec (relative paths): pyinstaller WeftScan.spec
requirements.txt
README.md / ABOUT.md / ARCHITECTURE.md / AGENTS.md
docs/setup-guide.md
weftscan/
  core/        models, utils, ping, hostnames, identify, network (NetworkScanner)
  analysis/    audit (TLS/HTTP), exposure (risk heuristics), report (HTML/PDF)
  actions/     exporter (CSV/JSON), menu (web/RDP/WoL), wol
  nettools/    tools (diagnostics), monitor, profiles (scan profiles + parse_ports)
  interface/   ui, widgets, tools_tab, monitor_tab, settings, theme
  i18n.py      text catalogue; the app forces English
  main.py / launcher.py / assets/
tests/         regression tests, standard library only
```

## Layer rule

Each layer imports only from the layers above it in this list:
`core` → `analysis` → `actions` → `nettools` → `interface`.
`core` never imports `interface`, so the engine runs headless. The package
`__init__.py` never imports the interface.

## Conventions

- Python 3.10+ (3.13 recommended), `from __future__ import annotations`.
- Pure data in `core/models.py`; the engine never imports tkinter.
- All source files are UTF-8; pass `encoding="utf-8"` to `open()`/`write_text`.
- The GUI uses Tkinter/ttk only, styled in `theme.setup_style` (flat styles on
  `clam`). Do not add GUI libraries. Use the colour tokens in `theme.PALETTE`;
  the blue accent is reserved for the primary action, selection and the map.
- Never set fonts through `option_add("*Font")`: it overrides every ttk
  style. Fonts belong in the ttk styles. Never name an attribute `_options`, `_w`, `tk` or
  another `tkinter.Misc` internal on the window: `self._options` once broke
  the clipboard.
- Tools return a `ToolResult` and never raise.
- User-visible text is English.

## Tests

```powershell
python -m unittest discover -s tests -t . -v
```

GUI tests create a real window (hidden) and redirect
`interface.settings.SETTINGS_FILE` to a temporary folder, so they never
touch the user's preferences.

## Commands

- Run: `python -m weftscan.main` (run as administrator for the full ARP sweep).
- Build: `pyinstaller WeftScan.spec` → `dist/WeftScan.exe`.
- The spec points at `launcher.py`, not `main.py`, because PyInstaller does
  not resolve the relative imports of `main.py`. New modules must be added to
  `hiddenimports` in the spec.

## Design notes

- **Engine → window event contract.** `interface/ui.py` listens for the exact
  phases `NetworkScanner` emits (`Device`, `Discovery`, `Ports`, `Models`,
  `Fingerprint`, `Finished`, `Cancelled`, `Error`). Renaming one in
  `core/network.py` makes `tests/test_ui.py` fail on purpose.
- The scan worker always ends by posting `WORKER_DONE`, even if the engine
  raises; it is the only signal that re-enables the buttons. *Stop* only
  requests cancellation and waits for it.
- The results table (`widgets.DeviceTree`) is a `ttk.Treeview` with the
  columns in `TREE_COLUMNS`. Rows are updated in place with `upsert_device`,
  so selection and expanded rows survive; only filtering or sorting rebuilds.
- `Device.open_ports` also holds closed/filtered ports: always filter with
  `port.is_open` (see `widgets.open_ports`).
- Port banners go through `identify.summarise_banner`; raw greetings carry
  binary (MySQL) that must never reach the table.
- Risk is computed at the end of a scan with `analysis.exposure`
  (offline heuristics, no extra traffic).
- `cli.py` must stay headless: it may import core, analysis, actions and
  nettools, never `interface`. `tests/test_cli.py` drives it with a fake
  scanner.
- Custom names/notes (`settings.device_labels`), "gone" detection
  (`settings.last_scan`, only compared for the same range) and auto-rescan
  live in `ui.py`; all key devices with `widgets.device_key`.
- New-device detection keys on MAC (IP when no MAC). The first scan only
  builds the baseline; *Settings › Forget known devices* resets it.
- Treeview column widths and row heights are pixels: always pass them
  through `theme.px()` so they scale with the screen DPI.
- Icons are PNGs drawn by `tools/make_icons.py` (Pillow, design time only)
  into `assets/icons`; `theme.Icons` loads them and composites the status
  badge. A new device category needs a glyph there and a key in
  `core/devicetype.CATEGORY_NAMES`.
- README screenshots use `docs/sample-results.json` (fictional data from
  `tools/make_sample.py`). Never commit screenshots of a real network.
- Adding a tool: function in `nettools/tools.py` + one `Tool` entry in
  `interface/tools_tab.TOOLS`. Adding a profile: one `ScanProfile` in
  `nettools/profiles.PROFILES`.
