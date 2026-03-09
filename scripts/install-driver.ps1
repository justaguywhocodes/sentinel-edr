#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Install and start the SentinelPOC kernel driver.

.DESCRIPTION
    1. Verifies the driver binary exists
    2. Signs the driver with the test certificate (if not already signed)
    3. Creates the driver service via sc.exe
    4. Starts the driver service
    5. Verifies the driver is running

.PARAMETER DriverPath
    Path to sentinel-drv.sys. Defaults to build\bin\Release\sentinel-drv.sys.

.PARAMETER ServiceName
    Name for the driver service. Defaults to SentinelDrv.

.NOTES
    Run setup-testsigning.ps1 first and reboot if needed.
    Run from an elevated PowerShell prompt.
#>

param(
    [string]$DriverPath = "$PSScriptRoot\..\build\bin\Release\sentinel-drv.sys",
    [string]$ServiceName = "SentinelDrv",
    [string]$DisplayName = "SentinelPOC Kernel Driver",
    [string]$CertSubject = "CN=SentinelPOC Test Signing",
    [switch]$SkipSign
)

$ErrorActionPreference = "Stop"

Write-Host "=== SentinelPOC Driver Install ===" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Verify driver binary ─────────────────────────────────────────────

Write-Host "[1/4] Verifying driver binary..." -ForegroundColor Yellow

$DriverPath = (Resolve-Path $DriverPath -ErrorAction SilentlyContinue).Path
if (-not $DriverPath -or -not (Test-Path $DriverPath)) {
    Write-Error "Driver binary not found. Build the project first: cmake --build build --config Release"
}

Write-Host "  Found: $DriverPath" -ForegroundColor Green

# ── Step 2: Sign driver ─────────────────────────────────────────────────────

if (-not $SkipSign) {
    Write-Host "[2/4] Signing driver with test certificate..." -ForegroundColor Yellow

    $cert = Get-ChildItem "Cert:\CurrentUser\My" | Where-Object { $_.Subject -eq $CertSubject }
    if (-not $cert) {
        Write-Error "Test certificate not found. Run setup-testsigning.ps1 first."
    }

    # Copy driver to a working location if needed
    $driverDir = Split-Path $DriverPath
    $driverFile = Split-Path $DriverPath -Leaf

    $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if (-not $signtool) {
        # Try to find signtool in Windows SDK
        $sdkPaths = @(
            "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe",
            "C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
        )
        foreach ($path in $sdkPaths) {
            if (Test-Path $path) {
                $signtool = Get-Item $path
                break
            }
        }
    }

    if (-not $signtool) {
        Write-Warning "signtool.exe not found. Skipping signing — driver may fail to load."
    } else {
        & $signtool sign /v /s My /n $CertSubject /fd SHA256 $DriverPath 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  Driver signed successfully." -ForegroundColor Green
        } else {
            Write-Warning "Signing failed. Driver may not load without a valid signature."
        }
    }
} else {
    Write-Host "[2/4] Skipping signing (--SkipSign)." -ForegroundColor DarkGray
}

# ── Step 3: Create driver service ────────────────────────────────────────────

Write-Host "[3/4] Creating driver service..." -ForegroundColor Yellow

$existingService = sc.exe query $ServiceName 2>&1
if ($existingService -match "SERVICE_NAME") {
    Write-Host "  Service '$ServiceName' already exists. Stopping for reinstall..." -ForegroundColor DarkYellow
    sc.exe stop $ServiceName 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName 2>&1 | Out-Null
    Start-Sleep -Seconds 1
}

$sysPath = $DriverPath -replace '/', '\'
sc.exe create $ServiceName `
    type= kernel `
    binPath= "$sysPath" `
    DisplayName= "$DisplayName" `
    start= demand `
    2>&1 | Out-Null

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to create driver service."
}

Write-Host "  Service '$ServiceName' created (demand start)." -ForegroundColor Green

# ── Step 4: Start driver ────────────────────────────────────────────────────

Write-Host "[4/4] Starting driver..." -ForegroundColor Yellow

sc.exe start $ServiceName 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Failed to start driver. Check Event Viewer > System for details."
    Write-Host "  Common causes:" -ForegroundColor DarkYellow
    Write-Host "    - Test-signing not enabled (run setup-testsigning.ps1 + reboot)"
    Write-Host "    - Secure Boot is enabled (disable in BIOS/UEFI)"
    Write-Host "    - Driver Verifier flagged an issue"
    Write-Host ""
    Write-Host "  To debug, attach WinDbg and check: !analyze -v"
} else {
    Write-Host "  Driver started successfully." -ForegroundColor Green
}

# ── Verify ───────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "=== Service Status ===" -ForegroundColor Cyan
sc.exe query $ServiceName

Write-Host ""
Write-Host "To stop:      sc.exe stop $ServiceName" -ForegroundColor DarkGray
Write-Host "To uninstall: .\uninstall-driver.ps1" -ForegroundColor DarkGray
