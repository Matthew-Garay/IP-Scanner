# -*- mode: python ; coding: utf-8 -*-
# IP Inspector build spec (lives in the project root).
# Build with:  pyinstaller IP_Inspector.spec   ->  dist/IP_Inspector.exe
# Relative paths only: works from any folder or PC.

a = Analysis(
    ['ip_inspector/launcher.py'],
    pathex=['.'],
    binaries=[],
    datas=[('ip_inspector/assets', 'assets')],
    hiddenimports=['ip_inspector', 'ip_inspector.interface.ui', 'ip_inspector.interface.theme', 'ip_inspector.interface.widgets', 'ip_inspector.interface.tools_tab', 'ip_inspector.interface.monitor_tab', 'ip_inspector.interface.settings', 'ip_inspector.core.network', 'ip_inspector.core.models', 'ip_inspector.core.utils', 'ip_inspector.core.identify', 'ip_inspector.core.hostnames', 'ip_inspector.core.ping', 'ip_inspector.analysis.audit', 'ip_inspector.analysis.exposure', 'ip_inspector.analysis.report', 'ip_inspector.nettools.tools', 'ip_inspector.nettools.monitor', 'ip_inspector.nettools.profiles', 'ip_inspector.actions.exporter', 'ip_inspector.actions.menu', 'ip_inspector.actions.wol', 'ip_inspector.i18n', 'ip_inspector.cli'],
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
    name='IP_Inspector',
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
    icon='ip_inspector/assets/icon.ico',
)
