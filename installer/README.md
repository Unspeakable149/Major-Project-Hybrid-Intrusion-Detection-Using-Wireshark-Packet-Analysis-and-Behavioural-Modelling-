# Hybrid IDS — Installer Build Guide

This folder contains everything needed to build a standalone Windows
installer (`HybridIDS-Setup-x.y.z.exe`) for the project. End users do not
need this folder. Developers use it to produce a release artifact for
the GitHub Releases page.

## Files

| File | Purpose |
|---|---|
| `launcher.py` | App entry point. Spawns the backend silently, starts the Streamlit dashboard, parks a tray icon. PyInstaller compiles this into `HybridIDS.exe`. |
| `HybridIDS.spec` | PyInstaller configuration. Lists bundled data, hidden imports, exe metadata. |
| `version_info.txt` | Embedded version resource for `HybridIDS.exe` (right-click → Properties → Details). |
| `installer.iss` | Inno Setup script. Builds the branded `HybridIDS-Setup-*.exe`. Detects tshark, registers uninstaller, adds Start Menu shortcuts. |
| `eula.txt` | MIT license text shown on the installer's License page. |
| `build.ps1` | One-shot build pipeline: PyInstaller + Inno Setup. |

## Prerequisites

1. **Python 3.10+** with these packages (install once):
   ```
   pip install streamlit pandas scikit-learn joblib pyinstaller pystray Pillow
   ```
2. **Inno Setup 6** — https://jrsoftware.org/isinfo.php (only needed if you want the branded installer; PyInstaller alone produces a portable folder).
3. **Trained models** present in `Dashboard/`:
   - `rf_model.pkl`
   - `rf_scaler.pkl`

   Generate them by running the training pipeline at the project root:
   ```
   python Dashboard\advanced_parser.py
   python Dashboard\feature_engineer.py
   python Dashboard\trainai_rf.py
   ```

## Build

From the project root, in PowerShell:

```
.\installer\build.ps1
```

The script:

1. Verifies trained `.pkl` artifacts exist.
2. Runs `pyinstaller installer\HybridIDS.spec --clean --noconfirm`
   → produces `dist\HybridIDS\` (~250–400 MB portable folder).
3. Runs `iscc installer\installer.iss`
   → produces `installer\output\HybridIDS-Setup-<version>.exe` (~100–150 MB compressed).

If Inno Setup is missing, the script still produces the PyInstaller folder, which can be zipped and distributed as a portable build.

## Publishing a Release

1. Bump version in `installer.iss` (`MyAppVersion`) and `version_info.txt` (both `filevers` and string `FileVersion`/`ProductVersion`).
2. Run `.\installer\build.ps1`.
3. Smoke-test the installer in a clean VM (recommended).
4. Create a new GitHub Release:
   - Tag: `v1.0.0`
   - Title: `Hybrid IDS v1.0.0`
   - Upload `installer\output\HybridIDS-Setup-1.0.0.exe` as the release asset.
5. Update the project root README to link to the latest release download.

## Smart Screen Warning

The installer is unsigned. On first run Windows SmartScreen shows a blue warning. Users click **More info → Run anyway**. To suppress this entirely, purchase an EV code-signing certificate (Sectigo / DigiCert / SSL.com, ~$200/yr) and sign both `HybridIDS.exe` and `HybridIDS-Setup-*.exe` with `signtool sign /td sha256 ...`.

## What the Installer Does

1. Welcome → License (`eula.txt`) → Install Location → Start Menu → ready.
2. Optional task: create a Desktop shortcut.
3. Detects Wireshark / tshark. If missing, prompts the user to open the Wireshark download page before continuing.
4. Copies the PyInstaller bundle to `C:\Program Files\Hybrid IDS\`.
5. Registers in **Settings → Apps & Features** with publisher / support URL / version metadata.
6. Adds Start Menu group with shortcuts to the app and dashboard URL.
7. Requests UAC elevation when the app launches (tshark + netsh require it).

## What Users See After Install

- Start Menu → **Hybrid IDS** → click.
- UAC prompt. Approve.
- Tray icon (green shield) appears.
- Default browser opens to the dashboard.
- Right-click tray icon → **Open Dashboard** / **Stop and Exit**.

## Troubleshooting Build Errors

| Error | Cause | Fix |
|---|---|---|
| `Required model artifact missing` | `.pkl` not trained | Run the training pipeline first |
| `pyinstaller: command not found` | Not installed in active Python | `pip install pyinstaller` |
| `ISCC.exe not found` | Inno Setup not installed | Install Inno Setup 6 |
| Streamlit fails to start inside frozen exe | File-watcher not disabled | Already handled in `launcher.py` via `STREAMLIT_SERVER_FILE_WATCHER_TYPE=none` |
| Antivirus quarantines `HybridIDS.exe` | PyInstaller bootloader heuristic | Whitelist locally, or sign the exe |
