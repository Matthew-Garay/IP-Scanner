# Setup Guide - IP Inspector

This guide helps you install and run IP Inspector locally.

## Prerequisites

- Windows 10 or Windows 11
- Python 3.10 or later (3.13 recommended)
- Administrator rights for the full discovery sweep (optional: without them
  the app runs in a limited mode)

## Installation

1. Clone the repository:
   ```powershell
   git clone https://github.com/Matthew-Garay/IP-Scanner.git
   cd IP-Scanner
   ```

2. Create and activate a virtual environment:
   ```powershell
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   ```

3. Install the dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

4. Run the application (ideally from an administrator terminal):
   ```powershell
   python -m ip_inspector.main
   ```

## First scan

1. The range of your local network is filled in automatically
   (for example `192.168.1.0/24`). You can also pick an adapter or type
   any range: `10.0.0.1-50`, `192.168.1.10`, or several separated by commas.
2. Choose a profile. *Standard* is a good default; *Full* checks ports
   1-1024; *Ping sweep only* just lists the live hosts.
3. Press **Scan** (F5). Click a device to see its details, right-click it for
   actions.

## Running the tests

```powershell
python -m unittest discover -s tests -t . -v
```

## Building the executable

```powershell
pip install pyinstaller
pyinstaller IP_Inspector.spec
# Output: dist\IP_Inspector.exe
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Devices show no MAC address | Run as administrator (Settings › Restart as administrator) |
| Scan is slow | Use the *Quick* profile or lower the timeout in Options (F8) |
| Too many sockets / errors on a big range | Lower *Threads* in Options |
| Traceroute or WHOIS fails | Those tools need `tracert` / network access to WHOIS servers |

## Responsible use

This tool probes network devices. Only use it on networks you own or are
authorised to test.
