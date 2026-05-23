# =============================================================
#   BlackPrism v4.0 — Windows Dependency Installation Script
#   Run in PowerShell as Administrator
# =============================================================

Write-Host ""
Write-Host "╔══════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       BlackPrism v4.0 — Windows Setup        ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check for Administrator privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "⚠️  WARNING: For best results installing tools, run this PowerShell script as Administrator." -ForegroundColor Yellow
    Write-Host ""
}

# 1. Check/Install Git
Write-Host "▶ Checking Git..." -ForegroundColor White
if (Get-Command git -ErrorAction SilentlyContinue) {
    Write-Host "  ✅ Git is already installed." -ForegroundColor Green
} else {
    Write-Host "  ℹ️  Git is not installed. Installing Git via winget..." -ForegroundColor Cyan
    winget install --id Git.Git -e --silent
    Write-Host "  ✅ Git installed successfully. Restart PowerShell after setup." -ForegroundColor Green
}

# 2. Check/Install Visual Studio Build Tools
Write-Host "`n▶ Checking Microsoft Visual Studio C++ Build Tools..." -ForegroundColor White
$vsInstalled = $false
$pathsToCheck = @(
    "${env:ProgramFiles(x86)}\Microsoft Visual Studio",
    "${env:ProgramFiles}\Microsoft Visual Studio"
)
foreach ($path in $pathsToCheck) {
    if (Test-Path $path) { $vsInstalled = $true }
}

if ($vsInstalled) {
    Write-Host "  ✅ Visual Studio Build Tools / IDE detected." -ForegroundColor Green
} else {
    Write-Host "  ℹ️  Visual Studio C++ Build Tools not found. Installing C++ compiler..." -ForegroundColor Cyan
    Write-Host "  This may take a few minutes..." -ForegroundColor Yellow
    winget install --id Microsoft.VisualStudio.2022.BuildTools --override "--passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended" -e
    Write-Host "  ✅ C++ Build Tools installation triggered successfully." -ForegroundColor Green
}

# 3. Check/Install Rust
Write-Host "`n▶ Checking Rust (rustup)..." -ForegroundColor White
if (Get-Command rustc -ErrorAction SilentlyContinue) {
    Write-Host "  ✅ Rust is already installed: $((rustc --version))" -ForegroundColor Green
    Write-Host "  Updating Rust to the latest stable toolchain..." -ForegroundColor Cyan
    rustup update stable
} else {
    Write-Host "  ℹ️  Rust is not installed. Downloading rustup-init.exe..." -ForegroundColor Cyan
    $rustupUrl = "https://win.rustup.rs/x86_64"
    $rustupPath = "$env:TEMP\rustup-init.exe"
    Invoke-WebRequest -Uri $rustupUrl -OutFile $rustupPath
    Write-Host "  Launching Rust installer..." -ForegroundColor Yellow
    Start-Process -FilePath $rustupPath -ArgumentList "-y --default-toolchain stable" -Wait
    Remove-Item $rustupPath
    
    # Reload environment variables
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    Write-Host "  ✅ Rust installed successfully." -ForegroundColor Green
}

# 4. Check WebView2
Write-Host "`n▶ Checking Microsoft Edge WebView2..." -ForegroundColor White
$webviewKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" -Name "pv" -ErrorAction SilentlyContinue
if ($null -ne $webviewKey) {
    Write-Host "  ✅ WebView2 Runtime detected (Version $($webviewKey.pv))." -ForegroundColor Green
} else {
    Write-Host "  ℹ️  WebView2 Runtime not found. Installing WebView2 via winget..." -ForegroundColor Cyan
    winget install --id Microsoft.EdgeWebView2Runtime -e --silent
    Write-Host "  ✅ WebView2 Runtime installed successfully." -ForegroundColor Green
}

# 5. Ask to Compile
Write-Host ""
$choice = Read-Host "  ¿Do you want to compile BlackPrism now? [y/N]"
if ($choice -match '^[yY]$') {
    Write-Host "`n▶ Compiling BlackPrism v4.0 in release mode..." -ForegroundColor White
    if (Test-Path "Cargo.toml") {
        cargo build --release
        if ($LASTEXITCODE -eq 0) {
            Write-Host "`n🎉 BlackPrism v4.0 compiled successfully!" -ForegroundColor Green
            Write-Host "   Binary generated: .\target\release\blackprism-tauri.exe" -ForegroundColor Green
            Write-Host "   You can move this file anywhere to run the app." -ForegroundColor Cyan
        } else {
            Write-Host "`n❌ Error during compilation. Make sure to restart your PowerShell session so all environment variables load correctly." -ForegroundColor Red
        }
    } else {
        Write-Host "❌ Error: Execute this script in the root directory containing Cargo.toml." -ForegroundColor Red
    }
} else {
    Write-Host "`nTo compile manually later, run:" -ForegroundColor Cyan
    Write-Host "  cargo build --release" -ForegroundColor White
}
Write-Host ""
