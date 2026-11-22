# IP Inspector Network and Port Scanner

## A. Project Title and Executive Summary

IP Inspector is a Windows desktop application that scans the local network, discovers connected devices, checks open TCP ports, identifies each device's model and operating system, and audits its security posture. It also bundles everyday network diagnostics (ping, traceroute, DNS, WHOIS, TLS, subnet maths…) and a continuous host monitor. The problem it solves is giving visibility over the devices on a local network without installing complex tools or running a server. Its technological scope is local execution on Windows with Python 3.10+, with no data sent to external servers.

## B. System Architecture

The program follows a layered architecture where each layer only imports from the layers below it. The interface layer (CustomTkinter) talks to the user and sends requests to the actions layer. The actions layer coordinates with the analysis layer to interpret security findings. The analysis layer relies on the network and scanning layer to obtain device data. The network and scanning layer uses the domain models defined in the core layer. Data flows from the interface to the scanning engine, and results travel back the same way to be shown on screen. Long-running work runs on a worker thread that delivers results through a queue.Queue, and the main thread consumes them so the window never freezes. See [ARCHITECTURE.md](ARCHITECTURE.md) for details.

## C. Key Technical Features

- **Network scan:** host discovery (ARP sweep, ICMP and TCP probes) plus TCP port scanning, including VPN subnets.
- **Scan profiles:** Quick, Standard (top ~100 ports), Full (1-1024), IoT / Cameras, Ping sweep only, and Custom port lists such as `22,80,443,8000-8100`.
- **Scan options:** network adapter selector, timeout, thread count, hostname resolution and model identification toggles.
- **Results:** sortable, filterable table with expandable services per device, a details panel, risk score and security findings.
- **Change detection:** devices never seen before are flagged **NEW**, devices that stopped answering are listed as **gone** (Ctrl+D), and an optional **auto-rescan** (every 5-60 min) alerts you when something changes.
- **Your own names:** give any device a custom name and a note (F2); they follow its MAC address even when its IP changes. Favorites (★) are remembered between sessions.
- **Command line:** scan without the window and export to CSV/JSON, e.g. for scheduled tasks (see below).
- **Device actions (right-click):** open in browser, Remote Desktop, SSH, browse shared folders, rescan, full 1-65535 port scan, ping, traceroute, TLS certificate, HTTP security headers, Wake-on-LAN, copy IP/MAC, add to monitor.
- **Tools tab:** Ping, Traceroute, Port check, Wake-on-LAN, DNS lookup, Reverse DNS, DNS summary, Mail security (SPF/DMARC/MX), Zone transfer, WHOIS, TLS certificate, HTTP headers, Subnet calculator, Subnet split, IP-in-network, Network adapters, ARP table, Listening ports and Local exposure.
- **Monitor tab:** continuous reachability checks with latency, uptime, loss statistics, an event log and an alert sound when a host goes down.
- **Export and reports:** CSV / JSON export and HTML / PDF security reports.
- Light, dark and system themes; keyboard shortcuts for every main action.
- No persistent database and no network protocol of its own beyond local scanning; preferences live in `~/.ip_inspector/settings.json`.
- Responsible use: the tool probes other machines and must only be used with permission.

## D. Technology Stack Specification

| Category | Technology / Library |
|----------|----------------------|
| Language | Python 3.10+ (3.13 recommended) |
| GUI | CustomTkinter |
| Networking | scapy, psutil, mac-vendor-lookup |
| Packaging | PyInstaller |
| Operating system | Windows |

## E. Installation, Configuration and Deployment Guide

### System prerequisites

- Windows 10 or 11 (the application is designed for the Windows desktop).
- Python 3.10 or later.
- Administrator rights for the full discovery sweep (raw sockets and ARP). Without them the app still works in a limited mode and offers *Settings › Restart as administrator*.

### Clone and install

```powershell
git clone https://github.com/Matthew-Garay/IP-Scanner.git
cd IP-Scanner
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Environment configuration

This project needs no .env file or environment variables.

### Running in development

```powershell
python -m ip_inspector.main
```

### Command-line mode

```powershell
python -m ip_inspector 192.168.1.0/24 -p quick          # scan and print a table
python -m ip_inspector 10.0.0.1-50 --ports 22,80,443,8000-8100
python -m ip_inspector -o results.csv -o results.json   # local network, save both
python -m ip_inspector 192.168.1.0/24 --fail-on-risk 40 # exit code 3 if a host is risky
python -m ip_inspector --list-profiles
python -m ip_inspector --help
```

Without arguments, `python -m ip_inspector` opens the window.

### Keyboard shortcuts

| Key | Action |
|-----|--------|
| F5 / Esc | Start / stop the scan |
| Ctrl+R | Rescan the selected device |
| Ctrl+F | Filter the results |
| Ctrl+S / Ctrl+P | Export results / security report |
| Ctrl+T / Ctrl+M | Tools tab / Monitor tab |
| Ctrl+D / F2 | Changes since last scan / rename the selected device |
| F8 / F9 | Scan options / details panel |

### Tests

```powershell
python -m unittest discover -s tests -t . -v
```

### Production build

```powershell
pip install pyinstaller
pyinstaller IP_Inspector.spec   # -> dist\IP_Inspector.exe
```

## F. Authorship Credits

Developed by: Matthew Ilveneff Garay Perez
Email: 1911.garay.perez@gmail.com
