# phishing_detector.spec
# PyInstaller spec file for Email Phishing Detection System
#
# HOW TO BUILD:
#   pip install pyinstaller
#   pyinstaller phishing_detector.spec
#
# Output: dist/PhishingDetector.exe  (Windows)
#         dist/PhishingDetector      (Linux/Mac)

import os
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

# Project root (same folder as this .spec file)
ROOT = os.path.dirname(os.path.abspath(SPEC))

# ── Collect all submodules that PyInstaller might miss ───────────────────────
hidden = []
hidden += collect_submodules('dns')          # dnspython
hidden += collect_submodules('email')        # stdlib email module
hidden += collect_submodules('encodings')    # all text encodings
hidden += collect_submodules('tkinter')      # full tkinter
hidden += [
    'dns.resolver', 'dns.rdatatype', 'dns.rdataclass',
    'dns.rdata', 'dns.name', 'dns.exception',
    'colorama', 'requests', 'urllib3', 'charset_normalizer',
    'difflib', 'concurrent.futures', 'threading',
    'html', 'html.parser', 're', 'base64',
]

# ── Data files — embed samples and assets ────────────────────────────────────
datas = [
    # (source_path,  destination_inside_exe bundle)
    (os.path.join(ROOT, 'samples'), 'samples'),
    (os.path.join(ROOT, 'analyzers'), 'analyzers'),
    (os.path.join(ROOT, 'scoring'),   'scoring'),
    (os.path.join(ROOT, 'report'),    'report'),
]

a = Analysis(
    [os.path.join(ROOT, 'gui.py')],   # Entry point = GUI
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Trim fat — exclude heavy unused packages
        'matplotlib', 'numpy', 'pandas', 'scipy',
        'PIL', 'cv2', 'sklearn', 'torch', 'tensorflow',
        'IPython', 'jupyter', 'notebook',
        'test', 'unittest', 'pydoc',
        'xmlrpc', 'ftplib', 'imaplib', 'poplib',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='PhishingDetector',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,              # compress with UPX if available (smaller .exe)
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,         # False = no black terminal window (GUI only)
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon='assets/icon.ico',  # Uncomment if you add an icon file
    version_info=None,
)
