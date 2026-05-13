# Hybrid IDS — Release Build Pipeline
#
# Run from PowerShell at the project root:
#     .\installer\build.ps1
#
# Output:
#     dist\HybridIDS\                            <- PyInstaller bundle
#     installer\output\HybridIDS-Setup-1.0.0.exe <- Inno Setup installer
#
# Prerequisites (one-time):
#     - Python 3.10+ with: streamlit, pandas, scikit-learn, joblib,
#       pyinstaller, pystray, Pillow
#     - Inno Setup 6 installed (https://jrsoftware.org/isinfo.php)
#     - Trained model artifacts in Dashboard/ (rf_model.pkl, rf_scaler.pkl)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path "$PSScriptRoot\..").Path
Set-Location $ProjectRoot

Write-Host "=== Hybrid IDS Release Build ===" -ForegroundColor Cyan
Write-Host "Project root: $ProjectRoot"
Write-Host ""

# --- Preflight ---------------------------------------------------------------

$requiredArtifacts = @(
    "Dashboard\rf_model.pkl",
    "Dashboard\rf_scaler.pkl"
)
foreach ($a in $requiredArtifacts) {
    if (-not (Test-Path $a)) {
        Write-Host "[X] Missing artifact: $a" -ForegroundColor Red
        Write-Host "    Train the model first:"
        Write-Host "      python Dashboard\advanced_parser.py"
        Write-Host "      python Dashboard\feature_engineer.py"
        Write-Host "      python Dashboard\trainai_rf.py"
        exit 1
    }
}

try   { python -c "import pyinstaller" 2>$null }
catch { }
$pi = (Get-Command pyinstaller -ErrorAction SilentlyContinue)
if (-not $pi) {
    Write-Host "[X] PyInstaller not found. Install with: pip install pyinstaller" -ForegroundColor Red
    exit 1
}

$isccCandidates = @(
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe"
)
$iscc = $isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
    Write-Host "[!] Inno Setup not found. PyInstaller bundle will build, but" -ForegroundColor Yellow
    Write-Host "    HybridIDS-Setup.exe will NOT be produced."
    Write-Host "    Install from https://jrsoftware.org/isinfo.php and re-run."
}

# --- PyInstaller -------------------------------------------------------------

Write-Host "[1/2] Building PyInstaller bundle..." -ForegroundColor Cyan
if (Test-Path build)             { Remove-Item -Recurse -Force build }
if (Test-Path "dist\HybridIDS")  { Remove-Item -Recurse -Force "dist\HybridIDS" }

pyinstaller installer\HybridIDS.spec --clean --noconfirm
if ($LASTEXITCODE -ne 0) {
    Write-Host "[X] PyInstaller build failed." -ForegroundColor Red
    exit 1
}
Write-Host "[+] PyInstaller bundle: dist\HybridIDS\" -ForegroundColor Green
Write-Host ""

# --- Inno Setup --------------------------------------------------------------

if ($iscc) {
    Write-Host "[2/2] Building Inno Setup installer..." -ForegroundColor Cyan
    & $iscc installer\installer.iss
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[X] Inno Setup compile failed." -ForegroundColor Red
        exit 1
    }
    $installer = Get-ChildItem "installer\output\HybridIDS-Setup-*.exe" |
                 Sort-Object LastWriteTime -Descending |
                 Select-Object -First 1
    Write-Host ""
    Write-Host "[+] Installer ready: $($installer.FullName)" -ForegroundColor Green
    Write-Host "    Size: $([math]::Round($installer.Length / 1MB, 1)) MB"
} else {
    Write-Host "[2/2] Skipping Inno Setup step (compiler not found)." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Build complete ===" -ForegroundColor Cyan
