"""IP Inspector - network discovery, port analysis and security auditing.

Layout
------

The package is a stack of layers, and each one may only import from the ones
below it:

    core       - the engine: models, platform helpers, probing, the scanner
    analysis   - what the findings mean: risk, exposure, written reports
    actions    - what can be done to a device: open it, wake it, export it
    nettools   - the Tools tabs and continuous monitoring
    interface  - everything that touches tkinter
    i18n       - the bilingual catalogue, used by the reports and the window

Public surface::

    from ip_inspector import NetworkScanner, ScanRequest, Device
    from ip_inspector import tools, audit

The user interface is deliberately *not* imported here, so headless
consumers of the scanning core do not pay for the tkinter import.
"""

from .analysis import audit
from .analysis.audit import audit_device, audit_http, inspect_tls, risk_score
from .core.models import (
    Device,
    HttpReport,
    Port,
    ScanRequest,
    ScannerEvent,
    SecurityFinding,
    TlsReport,
    ToolResult,
)
from .core.network import NetworkScanner
from .nettools import tools

__author__ = "Matthew Garay"
__all__ = [
    "Device",
    "Port",
    "NetworkScanner",
    "ScanRequest",
    "ScannerEvent",
    "ToolResult",
    "TlsReport",
    "HttpReport",
    "SecurityFinding",
    "audit_device",
    "audit_http",
    "inspect_tls",
    "risk_score",
    "tools",
    "audit",
]