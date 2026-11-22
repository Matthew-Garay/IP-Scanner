"""Everything that touches tkinter.

The only layer allowed to know about widgets, and the only one the core may
never import.

    ui           - main window: menu bar, Scanner and Favorites tabs, scan flow
    widgets      - results table (DeviceTree) and device detail panel
    tools_tab    - Tools tab: diagnostics declared in one TOOLS table
    monitor_tab  - Monitor tab: continuous reachability checks and alerts
    settings     - user preferences persisted in ~/.ip_inspector/settings.json
    theme        - light and dark palettes
"""
