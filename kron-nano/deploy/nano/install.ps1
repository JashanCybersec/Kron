#Requires -Version 5.1
<#
.SYNOPSIS
    KRON Nano — Zero-interaction Windows installer

.DESCRIPTION
    Downloads and installs kron-nano as a Windows Service.
    Run as Administrator, or the script will self-elevate.

    One-liner install (paste in PowerShell as Administrator):
        irm https://get.kron.security/windows | iex

    Or download and run:
        powershell -ExecutionPolicy Bypass -File install.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Constants ──────────────────────────────────────────────────────────────────
$KRON_VERSION       = $env:KRON_VERSION  ?? '0.1.0'
$GITHUB_ORG         = 'kron-security'
$GITHUB_REPO        = 'kron-nano'
$ASSET_NAME         = 'kron-nano-windows-x86_64.exe'
$DOWNLOAD_URL       = "https://github.com/$GITHUB_ORG/$GITHUB_REPO/releases/latest/download/$ASSET_NAME"

$INSTALL_DIR        = 'C:\Program Files\KronNano'
$DATA_DIR           = 'C:\ProgramData\KronNano'
$BIN_PATH           = "$INSTALL_DIR\kron-nano.exe"
$CONFIG_PATH        = "$DATA_DIR\kron.toml"
$KEY_PATH           = "$DATA_DIR\jwt.key"
$PUB_PATH           = "$DATA_DIR\jwt.pub"
$LOG_DIR            = "$DATA_DIR\logs"
$SERVICE_NAME       = 'KronNano'
$SERVICE_DISPLAY    = 'KRON Nano SIEM'
$SERVICE_DESC       = 'KRON Nano — single-binary SIEM with DuckDB embedded storage'

# ── Colour helpers ─────────────────────────────────────────────────────────────
function Write-Step  { param($m) Write-Host "  [>] $m" -ForegroundColor Cyan   }
function Write-Ok    { param($m) Write-Host "  [+] $m" -ForegroundColor Green  }
function Write-Warn  { param($m) Write-Host "  [!] $m" -ForegroundColor Yellow }
function Write-Fail  { param($m) Write-Host "  [x] $m" -ForegroundColor Red; exit 1 }

# ── Banner ─────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ██╗  ██╗██████╗  ██████╗ ███╗   ██╗" -ForegroundColor DarkCyan
Write-Host "  ██║ ██╔╝██╔══██╗██╔═══██╗████╗  ██║" -ForegroundColor DarkCyan
Write-Host "  █████╔╝ ██████╔╝██║   ██║██╔██╗ ██║" -ForegroundColor DarkCyan
Write-Host "  ██╔═██╗ ██╔══██╗██║   ██║██║╚██╗██║" -ForegroundColor DarkCyan
Write-Host "  ██║  ██╗██║  ██║╚██████╔╝██║ ╚████║" -ForegroundColor DarkCyan
Write-Host "  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝  Nano $KRON_VERSION" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  Windows Installer" -ForegroundColor White
Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

# ── Self-elevation ─────────────────────────────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warn "Not running as Administrator — re-launching elevated..."
    $args = @('-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    Start-Process powershell -ArgumentList $args -Verb RunAs
    exit 0
}

# ── Stop existing service if running ──────────────────────────────────────────
$existingSvc = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
if ($existingSvc) {
    if ($existingSvc.Status -ne 'Stopped') {
        Write-Step "Stopping existing $SERVICE_NAME service..."
        Stop-Service -Name $SERVICE_NAME -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    Write-Step "Removing existing $SERVICE_NAME service..."
    sc.exe delete $SERVICE_NAME | Out-Null
    Start-Sleep -Seconds 1
}

# ── Create directories ─────────────────────────────────────────────────────────
Write-Step "Creating directories..."
$dirs = @(
    $INSTALL_DIR,
    $DATA_DIR,
    $LOG_DIR,
    "$DATA_DIR\data",
    "$DATA_DIR\bus",
    "$DATA_DIR\rules",
    "$DATA_DIR\models",
    "$DATA_DIR\archive",
    "$DATA_DIR\migrations"
)
foreach ($d in $dirs) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}
Write-Ok "Directories created"

# ── Download binary ────────────────────────────────────────────────────────────
# Use local build if available (running from source checkout)
$localBuild = Join-Path $PSScriptRoot '..\..\target\release\kron-nano.exe'
if (Test-Path $localBuild) {
    Write-Step "Found local build — copying..."
    Copy-Item $localBuild $BIN_PATH -Force
    Write-Ok "Installed from local build"
} else {
    Write-Step "Downloading kron-nano $KRON_VERSION for Windows..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $tmpExe = "$env:TEMP\kron-nano-download.exe"
        $wc = New-Object Net.WebClient
        $wc.Headers.Add('User-Agent', "kron-installer/$KRON_VERSION (Windows)")
        $wc.DownloadFile($DOWNLOAD_URL, $tmpExe)
        Copy-Item $tmpExe $BIN_PATH -Force
        Remove-Item $tmpExe -Force
        Write-Ok "Downloaded and installed kron-nano.exe"
    } catch {
        Write-Fail "Download failed: $_`n  Build from source: cargo build --release -p kron-nano"
    }
}

# ── RSA key pair generation (pure .NET, no OpenSSL required) ──────────────────
function ConvertTo-DerTlv {
    param([byte]$Tag, [byte[]]$Value)
    $len = $Value.Length
    if ($len -lt 0x80) {
        return [byte[]](@($Tag, [byte]$len) + $Value)
    } elseif ($len -le 0xFF) {
        return [byte[]](@($Tag, 0x81, [byte]$len) + $Value)
    } else {
        return [byte[]](@($Tag, 0x82, [byte]($len -shr 8), [byte]($len -band 0xFF)) + $Value)
    }
}

function ConvertTo-DerInteger {
    param([byte[]]$Bytes)
    # Trim leading zeros (keep at least one byte)
    $i = 0
    while ($i -lt ($Bytes.Length - 1) -and $Bytes[$i] -eq 0) { $i++ }
    $Bytes = $Bytes[$i..($Bytes.Length - 1)]
    # Prepend 0x00 if high bit set (ensures positive integer)
    if ($Bytes[0] -band 0x80) { $Bytes = [byte[]](@(0x00) + $Bytes) }
    return ConvertTo-DerTlv 0x02 $Bytes
}

function New-RsaKeyPair {
    param([string]$PrivPath, [string]$PubPath)

    if (Test-Path $PrivPath) {
        Write-Ok "JWT keys already exist — skipping generation"
        return
    }

    Write-Step "Generating RSA-2048 key pair..."
    $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048)
    $p   = $rsa.ExportParameters($true)

    # ── PKCS#1 RSAPrivateKey DER ──
    $ver = [byte[]](0x02, 0x01, 0x00)
    $seq = [byte[]](
        $ver +
        (ConvertTo-DerInteger $p.Modulus)    +
        (ConvertTo-DerInteger $p.Exponent)   +
        (ConvertTo-DerInteger $p.D)          +
        (ConvertTo-DerInteger $p.P)          +
        (ConvertTo-DerInteger $p.Q)          +
        (ConvertTo-DerInteger $p.DP)         +
        (ConvertTo-DerInteger $p.DQ)         +
        (ConvertTo-DerInteger $p.InverseQ)
    )
    $privDer = ConvertTo-DerTlv 0x30 $seq
    $privB64 = [Convert]::ToBase64String($privDer, 'InsertLineBreaks')
    "-----BEGIN RSA PRIVATE KEY-----`r`n$privB64`r`n-----END RSA PRIVATE KEY-----" |
        Set-Content -Path $PrivPath -Encoding ASCII

    # ── SubjectPublicKeyInfo DER ──
    $pubSeq  = ConvertTo-DerTlv 0x30 ([byte[]](
        (ConvertTo-DerInteger $p.Modulus) +
        (ConvertTo-DerInteger $p.Exponent)
    ))
    # BIT STRING: 0x00 unused-bits prefix + RSAPublicKey SEQUENCE
    $bitStr  = ConvertTo-DerTlv 0x03 ([byte[]](@(0x00) + $pubSeq))
    # OID rsaEncryption (1.2.840.113549.1.1.1) + NULL
    $oid     = [byte[]](0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00)
    $algoSeq = ConvertTo-DerTlv 0x30 $oid
    $spki    = ConvertTo-DerTlv 0x30 ([byte[]]($algoSeq + $bitStr))
    $pubB64  = [Convert]::ToBase64String($spki, 'InsertLineBreaks')
    "-----BEGIN PUBLIC KEY-----`r`n$pubB64`r`n-----END PUBLIC KEY-----" |
        Set-Content -Path $PubPath -Encoding ASCII

    # Lock down private key permissions
    $acl = Get-Acl $PrivPath
    $acl.SetAccessRuleProtection($true, $false)
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        'SYSTEM', 'Read', 'Allow')
    $acl.AddAccessRule($rule)
    $rule2 = [System.Security.AccessControl.FileSystemAccessRule]::new(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
        'FullControl', 'Allow')
    $acl.AddAccessRule($rule2)
    Set-Acl -Path $PrivPath -AclObject $acl

    Write-Ok "RSA-2048 key pair generated"
}

New-RsaKeyPair -PrivPath $KEY_PATH -PubPath $PUB_PATH

# ── Default tenant UUID ────────────────────────────────────────────────────────
$tenantId = [guid]::NewGuid().ToString()

# ── Write configuration ────────────────────────────────────────────────────────
if (-not (Test-Path $CONFIG_PATH)) {
    Write-Step "Writing default configuration..."

    # Escape backslashes for TOML
    $dataEsc    = $DATA_DIR.Replace('\', '\\')
    $keyEsc     = $KEY_PATH.Replace('\', '\\')
    $pubEsc     = $PUB_PATH.Replace('\', '\\')

    @"
# KRON Nano — Windows configuration
# Generated by installer on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# Edit this file then restart the KronNano service.

mode = "nano"

[duckdb]
path                        = "$dataEsc\\data\\events.duckdb"
memory_limit_mb             = 2048
threads                     = 4
migrations_dir              = "$dataEsc\\migrations"
cold_archive_dir            = "$dataEsc\\archive"
cold_storage_retention_days = 180
cold_archive_interval_hours = 24

[embedded_bus]
data_dir                    = "$dataEsc\\bus"
max_wal_size_mb             = 512
sync_writes                 = true
max_retry_count             = 3
backpressure_lag_threshold  = 100000

[auth]
jwt_private_key_path        = "$keyEsc"
jwt_public_key_path         = "$pubEsc"
jwt_expiry_secs             = 28800
max_failed_attempts         = 5
lockout_duration_secs       = 900

[collector]
grpc_addr                   = "0.0.0.0:50051"
http_addr                   = "0.0.0.0:8081"
syslog_udp_addr             = "0.0.0.0:514"
syslog_tcp_addr             = "0.0.0.0:6514"
heartbeat_timeout_secs      = 90
metrics_addr                = "0.0.0.0:9101"

[normalizer]
raw_tenant_ids              = ["$tenantId"]
geoip_db_path               = "$dataEsc\\GeoLite2-City.mmdb"
asset_cache_ttl_secs        = 300
asset_cache_size            = 10000
metrics_addr                = "0.0.0.0:9102"

[stream]
rules_dir                   = "$dataEsc\\rules"
models_dir                  = "$dataEsc\\models"
alert_threshold             = 70
tenant_ids                  = ["$tenantId"]

[alert]
# Add notification credentials to enable alerts (optional at install time)
whatsapp_token              = ""
whatsapp_phone_id           = ""
sms_api_key                 = ""
sms_sender_id               = "KRNSEC"
smtp_host                   = "smtp.example.com"
smtp_port                   = 587
smtp_username               = ""
smtp_password               = ""
smtp_from                   = "alerts@kron.local"
max_notifications_per_hour  = 10

[api]
listen_addr                 = "0.0.0.0:8080"
max_body_bytes              = 10485760
cors_origins                = ["*"]

[telemetry]
log_level                   = "info"
metrics_addr                = "0.0.0.0:9100"
"@ | Set-Content -Path $CONFIG_PATH -Encoding UTF8

    Write-Ok "Configuration written to $CONFIG_PATH"
} else {
    Write-Ok "Existing configuration found — skipping"
}

# ── Windows Firewall rules ─────────────────────────────────────────────────────
Write-Step "Configuring Windows Firewall..."
$fwRules = @(
    @{ Port = 8080;  Proto = 'TCP'; Name = 'KronNano-API';       Desc = 'KRON Nano Query API' },
    @{ Port = 8081;  Proto = 'TCP'; Name = 'KronNano-Collector-HTTP'; Desc = 'KRON Nano HTTP ingestion' },
    @{ Port = 50051; Proto = 'TCP'; Name = 'KronNano-gRPC';      Desc = 'KRON Nano gRPC (agent ingestion)' },
    @{ Port = 514;   Proto = 'UDP'; Name = 'KronNano-Syslog-UDP';Desc = 'KRON Nano syslog UDP' },
    @{ Port = 6514;  Proto = 'TCP'; Name = 'KronNano-Syslog-TCP';Desc = 'KRON Nano syslog TLS' },
    @{ Port = 9100;  Proto = 'TCP'; Name = 'KronNano-Metrics';   Desc = 'KRON Nano Prometheus metrics' }
)
foreach ($r in $fwRules) {
    $exists = Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue
    if (-not $exists) {
        New-NetFirewallRule `
            -DisplayName  $r.Name `
            -Description  $r.Desc `
            -Direction    Inbound `
            -Protocol     $r.Proto `
            -LocalPort    $r.Port `
            -Action       Allow `
            -Profile      Any `
            -Enabled      True | Out-Null
    }
}
Write-Ok "Firewall rules configured"

# ── Install Windows Service ────────────────────────────────────────────────────
Write-Step "Installing Windows Service '$SERVICE_NAME'..."

$svcArgs = "--config `"$CONFIG_PATH`""

# Use sc.exe directly for full control over service parameters
sc.exe create $SERVICE_NAME `
    binPath= "`"$BIN_PATH`" $svcArgs" `
    DisplayName= "$SERVICE_DISPLAY" `
    start= auto `
    obj= LocalSystem | Out-Null

sc.exe description $SERVICE_NAME "$SERVICE_DESC" | Out-Null

# Configure failure recovery: restart after 5s, 3 attempts
sc.exe failure $SERVICE_NAME reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null

# Set environment variables for the service via registry
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$SERVICE_NAME"
$envVars = @(
    "KRON_CONFIG=$CONFIG_PATH",
    "KRON_LOG_LEVEL=info",
    "KRON_DATA_DIR=$DATA_DIR",
    "RUST_LOG=kron_nano=info"
)
New-ItemProperty -Path $regPath -Name 'Environment' -Value $envVars -PropertyType MultiString -Force | Out-Null

Write-Ok "Service '$SERVICE_NAME' installed"

# ── Start service ──────────────────────────────────────────────────────────────
Write-Step "Starting $SERVICE_NAME..."
try {
    Start-Service -Name $SERVICE_NAME
    Start-Sleep -Seconds 3
    $svc = Get-Service -Name $SERVICE_NAME
    if ($svc.Status -eq 'Running') {
        Write-Ok "Service is running"
    } else {
        Write-Warn "Service status: $($svc.Status) — check Event Viewer for details"
    }
} catch {
    Write-Warn "Could not start service automatically: $_"
    Write-Warn "Start manually: Start-Service $SERVICE_NAME"
}

# ── Add binary to PATH ─────────────────────────────────────────────────────────
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($machinePath -notlike "*$INSTALL_DIR*") {
    [Environment]::SetEnvironmentVariable(
        'Path',
        "$machinePath;$INSTALL_DIR",
        'Machine'
    )
    Write-Ok "Added $INSTALL_DIR to system PATH"
}

# ── Done ───────────────────────────────────────────────────────────────────────
$ip = (Get-NetIPAddress -AddressFamily IPv4 |
       Where-Object { $_.InterfaceAlias -notmatch 'Loopback' } |
       Select-Object -First 1).IPAddress

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║          KRON Nano installed successfully!               ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Service  : $SERVICE_NAME  (auto-starts on boot)" -ForegroundColor White
Write-Host "  Config   : $CONFIG_PATH" -ForegroundColor White
Write-Host "  Data     : $DATA_DIR" -ForegroundColor White
Write-Host "  Tenant   : $tenantId" -ForegroundColor White
Write-Host ""
Write-Host "  Dashboard: " -NoNewline -ForegroundColor White
Write-Host "http://localhost:8080" -ForegroundColor Cyan
if ($ip) {
Write-Host "  Network  : " -NoNewline -ForegroundColor White
Write-Host "http://${ip}:8080" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "  Manage the service:" -ForegroundColor DarkGray
Write-Host "    Start   :  Start-Service $SERVICE_NAME" -ForegroundColor DarkGray
Write-Host "    Stop    :  Stop-Service $SERVICE_NAME" -ForegroundColor DarkGray
Write-Host "    Logs    :  Get-EventLog -LogName Application -Source $SERVICE_NAME -Newest 50" -ForegroundColor DarkGray
Write-Host "    Uninstall:  .\uninstall.ps1" -ForegroundColor DarkGray
Write-Host ""

# Open browser
Start-Sleep -Seconds 2
try { Start-Process 'http://localhost:8080' } catch {}
