#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enable test-signing mode for SentinelPOC driver development.

.DESCRIPTION
    Configures the system for loading test-signed kernel drivers:
    1. Enables test-signing via bcdedit
    2. Creates a self-signed code-signing certificate
    3. Exports the certificate for driver signing
    4. Adds the certificate to the Trusted Root store

    A reboot is required after running this script for test-signing to take effect.

.NOTES
    Run from an elevated PowerShell prompt.
    Only use on test/development VMs — never on production systems.
#>

param(
    [string]$CertSubject = "CN=SentinelPOC Test Signing",
    [string]$CertStoreLocation = "Cert:\CurrentUser\My",
    [string]$OutputDir = "$PSScriptRoot\..\certs"
)

$ErrorActionPreference = "Stop"

Write-Host "=== SentinelPOC Test-Signing Setup ===" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Enable test-signing ──────────────────────────────────────────────

Write-Host "[1/4] Enabling test-signing mode..." -ForegroundColor Yellow

$currentMode = bcdedit /enum "{current}" | Select-String "testsigning"
if ($currentMode -match "Yes") {
    Write-Host "  Test-signing is already enabled." -ForegroundColor Green
} else {
    bcdedit /set testsigning on
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to enable test-signing. Ensure Secure Boot is disabled in BIOS/UEFI."
    }
    Write-Host "  Test-signing enabled. Reboot required." -ForegroundColor Green
}

# ── Step 2: Create self-signed certificate ───────────────────────────────────

Write-Host "[2/4] Creating self-signed code-signing certificate..." -ForegroundColor Yellow

$existingCert = Get-ChildItem $CertStoreLocation | Where-Object { $_.Subject -eq $CertSubject }

if ($existingCert) {
    Write-Host "  Certificate already exists: $($existingCert.Thumbprint)" -ForegroundColor Green
    $cert = $existingCert
} else {
    $cert = New-SelfSignedCertificate `
        -Subject $CertSubject `
        -Type CodeSigningCert `
        -CertStoreLocation $CertStoreLocation `
        -NotAfter (Get-Date).AddYears(5) `
        -FriendlyName "SentinelPOC Driver Test Signing"

    Write-Host "  Created certificate: $($cert.Thumbprint)" -ForegroundColor Green
}

# ── Step 3: Export certificate ───────────────────────────────────────────────

Write-Host "[3/4] Exporting certificate..." -ForegroundColor Yellow

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$certPath = Join-Path $OutputDir "SentinelPOC-TestSign.cer"
Export-Certificate -Cert $cert -FilePath $certPath -Force | Out-Null
Write-Host "  Exported to: $certPath" -ForegroundColor Green

# ── Step 4: Add to Trusted Root store ────────────────────────────────────────

Write-Host "[4/4] Adding certificate to Trusted Root CA store..." -ForegroundColor Yellow

$rootStore = Get-ChildItem "Cert:\LocalMachine\Root" | Where-Object { $_.Subject -eq $CertSubject }
if ($rootStore) {
    Write-Host "  Certificate already in Trusted Root store." -ForegroundColor Green
} else {
    Import-Certificate -FilePath $certPath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
    Write-Host "  Added to Trusted Root store." -ForegroundColor Green
}

# ── Summary ──────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Certificate thumbprint: $($cert.Thumbprint)"
Write-Host "Certificate file:       $certPath"
Write-Host ""
Write-Host "To sign the driver after building:" -ForegroundColor Yellow
Write-Host "  signtool sign /v /s My /n `"$CertSubject`" /t http://timestamp.digicert.com sentinel-drv.sys"
Write-Host ""

$restartNeeded = -not ($currentMode -match "Yes")
if ($restartNeeded) {
    Write-Host "*** REBOOT REQUIRED for test-signing to take effect ***" -ForegroundColor Red
    Write-Host ""
    $restart = Read-Host "Restart now? (y/N)"
    if ($restart -eq 'y') {
        Restart-Computer -Force
    }
}
