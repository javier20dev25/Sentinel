# Sentinel CLI Manual Setup Script
# This script manually adds Sentinel to your PATH by creating shims in the 'win-unpacked' folder.
# Run this from PowerShell as Administrator.

$ProjectRoot = Get-Location
$UnpackedDir = Join-Path $ProjectRoot "dist-electron\win-unpacked"
$ExePath = Join-Path $UnpackedDir "Sentinel.exe"

if (-Not (Test-Path $ExePath)) {
    Write-Error "❌ Error: Sentinel.exe not found in $UnpackedDir. Please run 'npm run electron:build' first."
    exit 1
}

Write-Host "🛡️ Setting up Sentinel CLI shims in $UnpackedDir..." -ForegroundColor Cyan

# Create sentinel.cmd
$SentinelCmd = @"
@echo off
"$ExePath" %*
"@
$SentinelCmd | Out-File -FilePath (Join-Path $UnpackedDir "sentinel.cmd") -Encoding ASCII

# Create sntl.cmd
$SntlCmd = @"
@echo off
"$ExePath" %*
"@
$SntlCmd | Out-File -FilePath (Join-Path $UnpackedDir "sntl.cmd") -Encoding ASCII

Write-Host "✅ Shims created successfully." -ForegroundColor Green

# Add to User PATH
Write-Host "🛡️ Adding $UnpackedDir to User PATH..." -ForegroundColor Cyan

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$UnpackedDir*") {
    $NewUserPath = "$UserPath;$UnpackedDir"
    [Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
    Write-Host "✅ Folder added to User PATH." -ForegroundColor Green
} else {
    Write-Host "ℹ️ Folder is already in User PATH." -ForegroundColor Yellow
}

Write-Host "🚀 Setup complete! Close all terminals and open a NEW PowerShell to test:" -ForegroundColor Green
Write-Host "   sentinel --version" -ForegroundColor White
Write-Host "   sntl --version" -ForegroundColor White
Write-Host "   sentinel open" -ForegroundColor White
