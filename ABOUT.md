# WeftScan Network and Port Scanner

## About

A Windows desktop application that scans the local network, discovers connected devices, checks open TCP ports, identifies each device's model and operating system and audits its security posture. It gives visibility over the devices on a local network without installing complex tools or running a server. Runs locally on Windows with Python, with no data sent to external servers.

## Main features

- Network scan: host discovery and TCP port scanning with six profiles (Quick, Standard, Full, IoT, Ping sweep, Custom), including VPN subnets.
- Security audit: exposure findings and a risk score per device, TLS and HTTP header checks.
- Network tools: ping, traceroute, port check, DNS, WHOIS, mail security, subnet calculator, ARP table, listening ports, Wake-on-LAN.
- Change detection: new devices are flagged against earlier scans; favorites are remembered.
- Monitor: continuous availability checks with uptime statistics and alerts.
- CSV / JSON export (reopenable) and HTML / PDF reports.
- Native Windows interface: results grid with shared folders, property panel, remote shutdown/restart and Wake-on-LAN.

## Technology stack

| Category | Technology |
|----------|------------|
| Language | Python 3.10+ |
| GUI | Tkinter / ttk (native Windows controls) |
| Networking | scapy, psutil, mac-vendor-lookup |
| Packaging | PyInstaller |
| Operating system | Windows |

## Credits

Developed by: Matthew Ilveneff Garay Perez
Email: 1911.garay.perez@gmail.com
