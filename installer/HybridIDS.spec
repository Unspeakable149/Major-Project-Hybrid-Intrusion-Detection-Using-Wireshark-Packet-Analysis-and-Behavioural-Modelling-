# PyInstaller spec for Hybrid IDS launcher.
#
# Build:
#     pyinstaller installer/HybridIDS.spec --clean --noconfirm
#
# Output: dist/HybridIDS/  (one-folder bundle, faster startup than one-file)

import os
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

ROOT = Path(SPECPATH).resolve().parent  # project root (one level above installer/)
DASHBOARD = ROOT / "Dashboard"

# Bundle the Dashboard directory as runtime data so launcher can find it
# via sys._MEIPASS at runtime.
datas = [
    (str(DASHBOARD / "app.py"),                          "Dashboard"),
    (str(DASHBOARD / "live_backend.py"),                 "Dashboard"),
    (str(DASHBOARD / "feature_engineer.py"),             "Dashboard"),
    (str(DASHBOARD / "advanced_parser.py"),              "Dashboard"),
    (str(DASHBOARD / "trainai_rf.py"),                   "Dashboard"),
    (str(DASHBOARD / "trainai.py"),                      "Dashboard"),
    (str(DASHBOARD / "evaluate_benchmark.py"),           "Dashboard"),
    (str(DASHBOARD / "debug_flags.py"),                  "Dashboard"),
    (str(DASHBOARD / "threat_intel.txt"),                "Dashboard"),
]

# Model artifacts are required at runtime. They are gitignored, so the
# build operator must have trained them locally before running pyinstaller.
for artifact in ("rf_model.pkl", "rf_scaler.pkl"):
    artifact_path = DASHBOARD / artifact
    if artifact_path.exists():
        datas.append((str(artifact_path), "Dashboard"))
    else:
        raise SystemExit(
            f"Required model artifact missing: {artifact_path}\n"
            f"Run the training pipeline first:\n"
            f"  python Dashboard/advanced_parser.py\n"
            f"  python Dashboard/feature_engineer.py\n"
            f"  python Dashboard/trainai_rf.py"
        )

# Streamlit ships static assets that PyInstaller doesn't auto-detect.
datas += collect_data_files("streamlit", include_py_files=False)

# Hidden imports Streamlit / sklearn / pandas rely on dynamically.
hiddenimports = []
hiddenimports += collect_submodules("streamlit")
hiddenimports += collect_submodules("sklearn")
hiddenimports += [
    "pandas",
    "numpy",
    "joblib",
    "pystray._win32",
    "PIL.Image",
    "PIL.ImageDraw",
]

a = Analysis(
    [str(ROOT / "installer" / "launcher.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        "matplotlib",   # not used at runtime
        "tkinter",      # streamlit uses watchdog, not tk
        "tcl",
        "tk",
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
    [],
    exclude_binaries=True,
    name="HybridIDS",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,           # tray app, no console window
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,               # supply installer/icon.ico to brand exe
    uac_admin=True,          # request UAC elevation on launch
    version=str(ROOT / "installer" / "version_info.txt") if (ROOT / "installer" / "version_info.txt").exists() else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="HybridIDS",
)
