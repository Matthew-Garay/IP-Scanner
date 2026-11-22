# Changelog

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
