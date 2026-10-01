"""Scanning engine: data model, platform helpers, probing and discovery.

The lowest layer of the application. Nothing in here may import the user
interface, or any of the layers above; the engine is usable headless, which
is what lets a scan run on a schedule with no display attached.

    models     - the data every other layer exchanges
    utils      - adapters, target planning, vendor lookup, platform probes
    ping       - ICMP probes (TTL and round-trip time) over the system ping
    hostnames  - PTR, NetBIOS and mDNS name resolution
    identify   - banner grabbing and model/OS fingerprints
    inventory  - the on-disk record of devices seen over time
    network    - the scanner itself: layer 2 sweep, layer 4 probe
"""
