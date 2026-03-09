#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Stop and uninstall the SentinelPOC kernel driver.

.DESCRIPTION
    1. Stops the driver service if running
    2. Deletes the driver service
    3. Optionally disables test-signing mode

.PARAMETER ServiceName
    Name of the driver service. Defaults to SentinelDrv.

.PARAMETER DisableTestSigning
    If specified, also disables test-signing mode (requires reboot).

.NOTES
    Run from an elevated PowerShell prompt.
#>

param(
    [string]$ServiceName = "SentinelDrv",
    [switch]$DisableTestSigning
)

$ErrorActionPreference = "Stop"

Write-Host "=== SentinelPOC Driver Uninstall ===" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Stop driver ─────────────────────────────────────────────────────

Write-Host "[1/3] Stopping driver service..." -ForegroundColor Yellow

$serviceQuery = sc.exe query $ServiceName 2>&1
if ($serviceQuery -match "STOPPED") {
    Write-Host "  Service is already stopped." -ForegroundColor Green
} elseif ($serviceQuery -match "RUNNING") {
    sc.exe stop $ServiceName 2>&1 | Out-Null
    Start-Sleep -Seconds 2

    $serviceQuery = sc.exe query $ServiceName 2>&1
    if ($serviceQuery -match "STOPPED") {
        Write-Host "  Service stopped." -ForegroundColor Green
    } else {
        Write-Warning "Service may not have stopped cleanly. A reboot may be required."
    }
} elseif ($serviceQuery -match "1060") {
    Write-Host "  Service '$ServiceName' does not exist. Nothing to uninstall." -ForegroundColor DarkYellow
    exit 0
} else {
    Write-Warning "Unexpected service state. Attempting to delete anyway."
}

# ── Step 2: Delete service ───────────────────────────────────────────────────

Write-Host "[2/3] Deleting driver service..." -ForegroundColor Yellow

sc.exe delete $ServiceName 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  Service '$ServiceName' deleted." -ForegroundColor Green
} else {
    Write-Warning "Failed to delete service. It may already be deleted or require a reboot."
}

# ── Step 3: Optionally disable test-signing ──────────────────────────────────

if ($DisableTestSigning) {
    Write-Host "[3/3] Disabling test-signing mode..." -ForegroundColor Yellow
    bcdedit /set testsigning off
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Test-signing disabled. Reboot required." -ForegroundColor Green
    } else {
        Write-Warning "Failed to disable test-signing."
    }
} else {
    Write-Host "[3/3] Test-signing left enabled (use -DisableTestSigning to turn off)." -ForegroundColor DarkGray
}

# ── Verify ───────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "=== Uninstall Complete ===" -ForegroundColor Cyan

$finalCheck = sc.exe query $ServiceName 2>&1
if ($finalCheck -match "1060") {
    Write-Host "Service '$ServiceName' is fully removed." -ForegroundColor Green
} else {
    Write-Host "Service may still be pending deletion. Reboot to complete." -ForegroundColor Yellow
}
