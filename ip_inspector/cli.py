"""Command-line interface: scan without opening the window.

Examples::

    python -m ip_inspector.cli                         # local network, Standard profile
    python -m ip_inspector.cli 192.168.1.0/24 -p quick
    python -m ip_inspector.cli 10.0.0.1-50 --ports 22,80,443,8000-8100
    python -m ip_inspector.cli 192.168.1.0/24 -o results.csv -o results.json
    python -m ip_inspector.cli --list-profiles

Exit codes: 0 success, 1 scan error or nothing to scan, 2 bad arguments,
130 interrupted. ``--fail-on-risk N`` exits 3 when any device scores N or
more, which lets a scheduled task alert on exposure.

Uses only the headless layers (core, analysis, actions, nettools): no tkinter.
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
from typing import Sequence, TextIO

from . import i18n
from .actions.exporter import export
from .analysis.exposure import exposure_findings, exposure_score
from .core.models import Device, ScannerEvent
from .core.network import NetworkScanner
from .core.utils import is_elevated, local_network_hint, plan_targets
from .nettools.profiles import CUSTOM, PROFILES, get_profile, parse_ports

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_RISK, EXIT_INTERRUPTED = 0, 1, 2, 3, 130

PHASE_TEXT = {
    "Discovery": "Discovering hosts",
    "Ports": "Scanning ports",
    "Models": "Identifying devices",
    "Fingerprint": "Fingerprinting",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ip_inspector",
        description="Scan a network for devices and open ports.",
        epilog="Only scan networks you own or are authorised to test.",
    )
    parser.add_argument("target", nargs="?", default="",
                        help="range to scan: 192.168.1.0/24, 10.0.0.1-50, 10.0.0.5 "
                             "(default: your local network)")
    parser.add_argument("-p", "--profile", default="standard",
                        choices=[p.key for p in PROFILES],
                        help="scan profile (default: standard)")
    parser.add_argument("--ports", help="custom port list, e.g. 22,80,443,8000-8100 "
                                        "(implies --profile custom)")
    parser.add_argument("-t", "--timeout", type=float, help="port timeout in seconds")
    parser.add_argument("-T", "--threads", type=int, help="concurrent probes")
    parser.add_argument("-i", "--interface", default="", help="network adapter name")
    parser.add_argument("--no-resolve", action="store_true", help="skip hostname resolution")
    parser.add_argument("--no-identify", action="store_true", help="skip model identification")
    parser.add_argument("--only-open", action="store_true",
                        help="list only hosts with open ports")
    parser.add_argument("-o", "--output", action="append", default=[], metavar="FILE",
                        help="write results to FILE (.csv or .json); repeatable")
    parser.add_argument("--fail-on-risk", type=int, metavar="SCORE",
                        help="exit with code 3 if any device has a risk score >= SCORE")
    parser.add_argument("-q", "--quiet", action="store_true", help="no progress output")
    parser.add_argument("--list-profiles", action="store_true",
                        help="show the available profiles and exit")
    return parser


def build_request(args: argparse.Namespace, target: str):
    """Turn parsed arguments into a ScanRequest (raises ValueError on bad ports)."""
    profile = CUSTOM if args.ports else get_profile(args.profile)
    overrides: dict = {"interface": args.interface}
    if args.ports:
        overrides["ports"] = parse_ports(args.ports)
    if args.timeout is not None:
        if args.timeout <= 0:
            raise ValueError("--timeout must be greater than 0")
        overrides["port_timeout"] = args.timeout
    if args.threads is not None:
        if not 1 <= args.threads <= 5000:
            raise ValueError("--threads must be between 1 and 5000")
        overrides["concurrency"] = args.threads
    if args.no_resolve:
        overrides["resolve_hostnames"] = False
    if args.no_identify:
        overrides["identify_models"] = False
    return profile.to_request(target, **overrides)


def format_table(devices: Sequence[Device]) -> str:
    """Fixed-width text table of the results."""
    headers = ("IP", "MAC", "NAME", "VENDOR", "TYPE", "RISK", "OPEN PORTS")
    rows = [(
        d.ip_address, d.mac_address or "-", (d.hostname or "-")[:24],
        (d.vendor or d.model or "-")[:26], i18n.device_type_label(d.device_type)[:14],
        str(d.risk_score) if d.risk_score else "-", d.ports_compact(),
    ) for d in devices]
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h)
              for i, h in enumerate(headers)]
    widths[-1] = len(headers[-1])        # last column is never padded

    def line(cells):
        return "  ".join(c.ljust(w) for c, w in zip(cells, widths)).rstrip()

    return "\n".join([line(headers), line("-" * w for w in widths), *map(line, rows)])


def run(argv: Sequence[str] | None = None, out: TextIO | None = None,
        err: TextIO | None = None, scanner: NetworkScanner | None = None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    parser = build_parser()
    args = parser.parse_args(argv)
    i18n.set_language("en")

    if args.list_profiles:
        for profile in PROFILES:
            print(f"{profile.key:<10} {profile.name:<16} {profile.ports_label():<16} "
                  f"{profile.description}", file=out)
        return EXIT_OK

    target = args.target or local_network_hint(args.interface)
    if not target:
        print("error: no target given and no local network found", file=err)
        return EXIT_ERROR
    plan = plan_targets(target)
    if plan.is_empty:
        print(f"error: invalid range: {', '.join(plan.problems) or target}", file=err)
        return EXIT_USAGE
    for path in args.output:
        if not path.lower().endswith((".csv", ".json")):
            print(f"error: {path}: output must end in .csv or .json", file=err)
            return EXIT_USAGE
    try:
        request = build_request(args, target)
    except ValueError as exc:
        print(f"error: {exc}", file=err)
        return EXIT_USAGE

    scanner = scanner or NetworkScanner()
    if not args.quiet:
        mode = "administrator" if is_elevated() else "limited mode (not elevated)"
        ports = f"{len(request.ports)} ports" if request.scan_ports_enabled else "no port scan"
        print(f"Scanning {target} ({plan.total} addresses, "
              f"{get_profile(request.profile).name}, {ports}, {mode})", file=err)

    stop = threading.Event()
    done = threading.Event()
    result: dict = {}

    def work() -> None:
        try:
            result["devices"] = scanner.scan(request, stop)
        except Exception as exc:  # noqa: BLE001 - reported below
            result["error"] = exc
        finally:
            done.set()

    started = time.monotonic()
    worker = threading.Thread(target=work, name="cli-scan", daemon=True)
    worker.start()
    try:
        _follow(scanner, done, err, quiet=args.quiet)
    except KeyboardInterrupt:
        stop.set()
        print("\nStopping…", file=err)
        done.wait(15)
        return EXIT_INTERRUPTED

    if "error" in result:
        print(f"error: scan failed: {result['error']}", file=err)
        return EXIT_ERROR
    devices: list[Device] = result.get("devices", [])
    for device in devices:
        device.findings = exposure_findings(device)
        device.risk_score = exposure_score(device)

    shown = [d for d in devices if not args.only_open or any(p.is_open for p in d.open_ports)]
    print(format_table(shown), file=out)
    elapsed = time.monotonic() - started
    with_ports = sum(1 for d in devices if any(p.is_open for p in d.open_ports))
    print(f"\n{len(devices)} device(s), {with_ports} with open ports, in {elapsed:.1f} s",
          file=out)

    for path in args.output:
        written = export(devices, path, extra={"range": target, "profile": request.profile})
        print(f"Saved {written}", file=out)

    if args.fail_on_risk is not None:
        risky = [d for d in devices if d.risk_score >= args.fail_on_risk]
        if risky:
            print(f"{len(risky)} device(s) at or above risk {args.fail_on_risk}: "
                  + ", ".join(d.ip_address for d in risky), file=err)
            return EXIT_RISK
    return EXIT_OK


def _follow(scanner: NetworkScanner, done: threading.Event, err: TextIO, quiet: bool) -> None:
    """Print progress events until the scan finishes."""
    last = ""
    while not done.is_set() or not scanner.event_queue.empty():
        try:
            event: ScannerEvent = scanner.event_queue.get(timeout=0.2)
        except Exception:  # queue.Empty
            continue
        if quiet or event.phase not in PHASE_TEXT:
            continue
        text = PHASE_TEXT[event.phase]
        if event.phase == "Ports" and event.total:
            text += f" {event.completed * 100 // event.total}%"
        if text != last:
            print(f"  {text}…", file=err)
            last = text


def main() -> int:
    return run()


if __name__ == "__main__":
    sys.exit(main())
