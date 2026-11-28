# Changelog

## 4.0

- New name: **WeftScan** (package `weftscan`, `WeftScan.exe`, repository
  Matthew-Garay/WeftScan). Settings from IP Scanner and IP Inspector are
  picked up on first start.
- New identity: indigo accent on cool grey, status colours taken from
  textile dyes, Bahnschrift for the wordmark and titles, and an app mark
  drawn as a piece of weave with one loose thread.
- The address map is now the weave: one stitch per address, raised and
  dyed where a device answered.

## 3.1

- System colours: white surfaces, black text and lines, one blue accent.
  Status colours (green, orange, red) only on badges and the address map;
  new devices are marked in black.
- The network range is detected automatically at start-up and re-checked
  every 15 seconds: moving to another network updates it. A range you type
  or pick is never overwritten; Settings › Detect my network range goes
  back to automatic.

## 3.0

- Renamed the project to IP Scanner (package `ip_scanner`, command
  `python -m ip_scanner`). Settings from `~/.ip_inspector` are read once
  and carried over.
- Device identification: SSDP/UPnP descriptions and mDNS/DNS-SD services are
  collected during every scan; randomized MAC addresses, this computer and
  the default gateway are recognised; every device gets one of 18
  categories with its own icon.
- New interface: navigation rail, command bar, address map, details panel
  with what each device announced, empty states, and a consistent flat
  theme with one accent colour.
- New application icon and icon set, drawn by `tools/make_icons.py`.
- Sample network (`docs/sample-results.json`) to try the app and for the
  README screenshots.
- The whole repository is English; the text catalogue keeps English only.

## 2.1

- Native interface on Tkinter/ttk instead of customtkinter.
- Shared folders under each Windows host, remote shutdown/restart,
  multi-select actions, reopening saved results.

## 2.0

- Command-line mode, device names and notes, change tracking, auto-rescan.
- Scan profiles, Tools and Monitor tabs, English interface.
