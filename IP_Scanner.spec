# -*- mode: python ; coding: utf-8 -*-
# IP Scanner build spec (lives in the project root).
# Build with:  pyinstaller IP_Scanner.spec   ->  dist/IP_Scanner.exe
# Relative paths only: works from any folder or PC.

a = Analysis(
    ['ip_scanner/launcher.py'],
    pathex=['.'],
    binaries=[],
    datas=[('ip_scanner/assets', 'ip_scanner/assets')],
    hiddenimports=['ip_scanner', 'ip_scanner.interface.ui', 'ip_scanner.interface.theme', 'ip_scanner.interface.widgets', 'ip_scanner.interface.tools_tab', 'ip_scanner.interface.monitor_tab', 'ip_scanner.interface.settings', 'ip_scanner.core.network', 'ip_scanner.core.discovery', 'ip_scanner.core.devicetype', 'ip_scanner.core.models', 'ip_scanner.core.utils', 'ip_scanner.core.identify', 'ip_scanner.core.hostnames', 'ip_scanner.core.ping', 'ip_scanner.analysis.audit', 'ip_scanner.analysis.exposure', 'ip_scanner.analysis.report', 'ip_scanner.nettools.tools', 'ip_scanner.nettools.monitor', 'ip_scanner.nettools.profiles', 'ip_scanner.actions.exporter', 'ip_scanner.actions.menu', 'ip_scanner.actions.wol', 'ip_scanner.i18n', 'ip_scanner.cli'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='IP_Scanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='ip_scanner/assets/icon.ico',
)
