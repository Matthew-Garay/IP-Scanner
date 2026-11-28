# -*- mode: python ; coding: utf-8 -*-
# WeftScan build spec (lives in the project root).
# Build with:  pyinstaller WeftScan.spec   ->  dist/WeftScan.exe
# Relative paths only: works from any folder or PC.

a = Analysis(
    ['weftscan/launcher.py'],
    pathex=['.'],
    binaries=[],
    datas=[('weftscan/assets', 'weftscan/assets')],
    hiddenimports=['weftscan', 'weftscan.interface.ui', 'weftscan.interface.theme', 'weftscan.interface.widgets', 'weftscan.interface.tools_tab', 'weftscan.interface.monitor_tab', 'weftscan.interface.settings', 'weftscan.core.network', 'weftscan.core.discovery', 'weftscan.core.devicetype', 'weftscan.core.models', 'weftscan.core.utils', 'weftscan.core.identify', 'weftscan.core.hostnames', 'weftscan.core.ping', 'weftscan.analysis.audit', 'weftscan.analysis.exposure', 'weftscan.analysis.report', 'weftscan.nettools.tools', 'weftscan.nettools.monitor', 'weftscan.nettools.profiles', 'weftscan.actions.exporter', 'weftscan.actions.menu', 'weftscan.actions.wol', 'weftscan.i18n', 'weftscan.cli'],
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
    name='WeftScan',
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
    icon='weftscan/assets/icon.ico',
)
