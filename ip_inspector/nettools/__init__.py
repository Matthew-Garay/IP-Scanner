"""The Tools and Quick Tools tabs: standalone diagnostics and monitoring.

Reads from :mod:`ip_inspector.core`. The ping probes it shares with the
scanner live in ``ip_inspector.core.ping`` so the engine never has to reach
into this layer.

    tools     - DNS, WHOIS, traceroute, subnet maths, local exposure
    monitor   - continuous reachability checks and alerts
    profiles  - canned port profiles
"""
