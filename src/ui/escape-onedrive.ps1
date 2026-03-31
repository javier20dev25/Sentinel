# Sentinel: Move Out of OneDrive & Fix Build
# This script moves your project to C:\sentinel to avoid OneDrive file locking issues.
# Run this from a FRESH PowerShell as Administrator.

$Source = "C:\Users\sleyt\OneDrive\Desktop\sentinel"
$Dest = "C:\sentinel"

if (Test-Path $Dest) {
    Write-Host "🛡️ Destination $Dest already exists. Removing old files..." -ForegroundColor Yellow
    Remove-Item -Path $Dest -Recurse -Force
}

Write-Host "🛡️ Moving project from OneDrive to $Dest..." -ForegroundColor Cyan
Copy-Item -Path $Source -Destination $Dest -Recurse -Force

Write-Host "✅ Project moved to $Dest." -ForegroundColor Green

# 2. Re-install and Build
Write-Host "🛡️ Installing dependencies and building in the new location..." -ForegroundColor Cyan
cd "$Dest\src\ui"

# Remove node_modules to ensure a clean state
if (Test-Path "node_modules") {
    Remove-Item -Path "node_modules" -Recurse -Force
}

npm install
npm run electron:build

Write-Host "🚀 Done! Try running the app or the setup script from $Dest\src\ui" -ForegroundColor Green
