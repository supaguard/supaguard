# ==============================================================================
#  SupaGuard Universal Windows PowerShell Installer
#  Usage in PowerShell:
#    iwr -useb https://raw.githubusercontent.com/supaguard/supaguard/main/install.ps1 | iex
# ==============================================================================

$ErrorActionPreference = "Stop"

Write-Host "`nInstalling SupaGuard for Windows...`n" -ForegroundColor Cyan

# 1. Check Python
$pyCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pyCmd = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pyCmd = "py -3"
} else {
    Write-Error "Python 3 is required. Please install Python from https://python.org or winget install Python.Python.3"
    exit 1
}

# 2. Setup install directory
$installDir = Join-Path $env:USERPROFILE ".supaguard\core"
$binDir = Join-Path $env:USERPROFILE ".supaguard\bin"

New-Item -ItemType Directory -Force -Path $installDir | Out-Null
New-Item -ItemType Directory -Force -Path $binDir | Out-Null

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (Test-Path (Join-Path $scriptDir "supaguard")) {
    Copy-Item -Recurse -Force (Join-Path $scriptDir "supaguard") $installDir
    Copy-Item -Recurse -Force (Join-Path $scriptDir "bin") $installDir
} else {
    Write-Host "Downloading SupaGuard package..."
    $zipPath = "$env:TEMP\supaguard.zip"
    Invoke-WebRequest -Uri "https://github.com/supaguard/supaguard/archive/refs/heads/main.zip" -OutFile $zipPath
    Expand-Archive -Path $zipPath -DestinationPath "$env:TEMP\supaguard-unzip" -Force
    Copy-Item -Recurse -Force "$env:TEMP\supaguard-unzip\supaguard-main\supaguard" $installDir
    Copy-Item -Recurse -Force "$env:TEMP\supaguard-unzip\supaguard-main\bin" $installDir
    Remove-Item -Force $zipPath
    Remove-Item -Recurse -Force "$env:TEMP\supaguard-unzip"
}

# 3. Create Windows Launcher
$launcherCmd = Join-Path $binDir "supaguard.cmd"
@"
@echo off
python "$installDir\bin\supaguard" %*
"@ | Set-Content -Path $launcherCmd

# 4. Add to User PATH if not present
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$binDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$binDir", "User")
    Write-Host "Added $binDir to User PATH." -ForegroundColor Green
}

Write-Host "`n[OK] SupaGuard successfully installed to: $binDir\supaguard.cmd`n" -ForegroundColor Green
Write-Host "To scan your project:  supaguard scan ." -ForegroundColor Cyan
Write-Host "To check engines:      supaguard doctor`n" -ForegroundColor Cyan
