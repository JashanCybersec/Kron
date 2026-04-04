#Requires -Version 5.1
<#
.SYNOPSIS
    KRON Nano — Windows uninstaller

.DESCRIPTION
    Stops and removes the KronNano service, binary, firewall rules,
    and optionally the configuration and data directories.

    Usage:
        powershell -ExecutionPolicy Bypass -File uninstall.ps1
        powershell -ExecutionPolicy Bypass -File uninstall.ps1 -KeepData
#>

param(
    [switch]$KeepData  # Pass -KeepData to preserve C:\ProgramData\KronNano
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

$INSTALL_DIR  = 'C:\Program Files\KronNano'
$DATA_DIR     = 'C:\ProgramData\KronNano'
$SERVICE_NAME = 'KronNano'

function Write-Step { param($m) Write-Host "  [>] $m" -ForegroundColor Cyan   }
function Write-Ok   { param($m) Write-Host "  [+] $m" -ForegroundColor Green  }
function Write-Warn { param($m) Write-Host "  [!] $m" -ForegroundColor Yellow }

# ── Self-elevation ─────────────────────────────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warn "Re-launching as Administrator..."
    $argStr = if ($KeepData) { '-KeepData' } else { '' }
    Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`" $argStr" -Verb RunAs
    exit 0
}

Write-Host ""
Write-Host "  KRON Nano Uninstaller" -ForegroundColor DarkCyan
Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

if ($KeepData) {
    Write-Warn "Running with -KeepData: config and data will be preserved"
} else {
    Write-Warn "ALL data in $DATA_DIR will be deleted."
    Write-Host ""
    $confirm = Read-Host "  Type YES to confirm uninstall"
    if ($confirm -ne 'YES') { Write-Host "  Aborted."; exit 0 }
}

Write-Host ""

# ── Stop and remove service ────────────────────────────────────────────────────
Write-Step "Stopping service..."
Stop-Service -Name $SERVICE_NAME -Force
Start-Sleep -Seconds 2
Write-Ok "Service stopped"

Write-Step "Removing service..."
sc.exe delete $SERVICE_NAME | Out-Null
Start-Sleep -Seconds 1
Write-Ok "Service removed"

# ── Remove firewall rules ──────────────────────────────────────────────────────
Write-Step "Removing firewall rules..."
$fwNames = @(
    'KronNano-API', 'KronNano-Collector-HTTP', 'KronNano-gRPC',
    'KronNano-Syslog-UDP', 'KronNano-Syslog-TCP', 'KronNano-Metrics'
)
foreach ($n in $fwNames) {
    Remove-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue
}
Write-Ok "Firewall rules removed"

# ── Remove from PATH ───────────────────────────────────────────────────────────
Write-Step "Removing from system PATH..."
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$newPath = ($machinePath -split ';' | Where-Object { $_ -ne $INSTALL_DIR }) -join ';'
[Environment]::SetEnvironmentVariable('Path', $newPath, 'Machine')
Write-Ok "PATH updated"

# ── Remove binary ──────────────────────────────────────────────────────────────
Write-Step "Removing install directory..."
if (Test-Path $INSTALL_DIR) {
    Remove-Item -Path $INSTALL_DIR -Recurse -Force
    Write-Ok "Removed $INSTALL_DIR"
} else {
    Write-Ok "Install directory not found — skipping"
}

# ── Remove data ────────────────────────────────────────────────────────────────
if (-not $KeepData) {
    Write-Step "Removing data directory..."
    if (Test-Path $DATA_DIR) {
        Remove-Item -Path $DATA_DIR -Recurse -Force
        Write-Ok "Removed $DATA_DIR"
    } else {
        Write-Ok "Data directory not found — skipping"
    }
} else {
    Write-Ok "Data preserved at $DATA_DIR"
}

Write-Host ""
Write-Host "  KRON Nano has been uninstalled." -ForegroundColor Green
Write-Host ""
