<#
.SYNOPSIS
    Raccoon C2 Team Server - Launcher (Windows)
.DESCRIPTION
    Starts the Raccoon C2 team server with colored ASCII banner,
    pre-flight checks, interactive configuration, and key display.
.EXAMPLE
    .\start_server.ps1
    .\start_server.ps1 -Port 443 -SSL
    .\start_server.ps1 -Key "base64key==" -Token "my-secret-token"
    .\start_server.ps1 -NoPrompt
#>
param(
    [int]$Port = 8443,
    [string]$Host_ = "0.0.0.0",
    [string]$Key = "",
    [string]$DeriveKey = "",
    [string]$Token = "",
    [switch]$SSL,
    [string]$Cert = "",
    [string]$CertKey = "",
    [switch]$NoPrompt
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ServerPy = Join-Path $ScriptDir "server.py"

# -- Banner --
Clear-Host
Write-Host ""
Write-Host "    ██████╗  █████╗  ██████╗ ██████╗ ██████╗  ██████╗ ███╗   ██╗" -ForegroundColor Red
Write-Host "    ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔═══██╗████╗  ██║" -ForegroundColor Red
Write-Host "    ██████╔╝███████║██║     ██║     ██║   ██║██║   ██║██╔██╗ ██║" -ForegroundColor Red
Write-Host "    ██╔══██╗██╔══██║██║     ██║     ██║   ██║██║   ██║██║╚██╗██║" -ForegroundColor Red
Write-Host "    ██║  ██║██║  ██║╚██████╗╚██████╗╚██████╔╝╚██████╔╝██║ ╚████║" -ForegroundColor Red
Write-Host "    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝" -ForegroundColor Red
Write-Host ""
Write-Host "     ██████╗██████╗    ████████╗███████╗ █████╗ ███╗   ███╗" -ForegroundColor DarkGray
Write-Host "    ██╔════╝╚════██╗   ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║" -ForegroundColor DarkGray
Write-Host "    ██║      █████╔╝      ██║   █████╗  ███████║██╔████╔██║" -ForegroundColor White
Write-Host "    ██║     ██╔═══╝       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║" -ForegroundColor DarkGray
Write-Host "    ╚██████╗███████╗      ██║   ███████╗██║  ██║██║ ╚═╝ ██║" -ForegroundColor DarkGray
Write-Host "     ╚═════╝╚══════╝      ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝" -ForegroundColor DarkGray
Write-Host ""
Write-Host "    ─────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "     🦝 T R A S H   P A N D A   P A W S" -ForegroundColor Red
Write-Host "    ─────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

# -- Pre-flight checks --
$Python = $null
foreach ($cmd in @("python", "python3")) {
    try {
        $p = Get-Command $cmd -ErrorAction Stop
        $Python = $p.Source
        break
    } catch {}
}

if (-not $Python) {
    Write-Host "  [X] " -ForegroundColor Red -NoNewline
    Write-Host "Python not found" -ForegroundColor White
    exit 1
}

$PyVer = & $Python --version 2>&1
Write-Host "  [+] " -ForegroundColor Green -NoNewline
Write-Host "Python        " -ForegroundColor White -NoNewline
Write-Host "$PyVer" -ForegroundColor DarkGray

# Check dependencies
$Missing = @()
foreach ($pkg in @("flask", "cryptography")) {
    $check = & $Python -c "import $pkg" 2>&1
    if ($LASTEXITCODE -ne 0) { $Missing += $pkg }
}

if ($Missing.Count -gt 0) {
    Write-Host "  [!] " -ForegroundColor Yellow -NoNewline
    Write-Host "Installing    " -ForegroundColor White -NoNewline
    Write-Host ($Missing -join ", ") -ForegroundColor DarkGray
    & $Python -m pip install @Missing --quiet 2>$null
}

$FlaskVer = & $Python -c "import importlib.metadata; print(importlib.metadata.version('flask'))" 2>$null
$CryptoVer = & $Python -c "import importlib.metadata; print(importlib.metadata.version('cryptography'))" 2>$null
Write-Host "  [+] " -ForegroundColor Green -NoNewline
Write-Host "Flask         " -ForegroundColor White -NoNewline
Write-Host "$FlaskVer" -ForegroundColor DarkGray
Write-Host "  [+] " -ForegroundColor Green -NoNewline
Write-Host "Cryptography  " -ForegroundColor White -NoNewline
Write-Host "$CryptoVer" -ForegroundColor DarkGray

# -- Interactive configuration --
$Proto = "http"
if ($SSL) { $Proto = "https" }

if (-not $NoPrompt -and -not $Key -and -not $DeriveKey) {
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Server Configuration" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  Listen host " -ForegroundColor Cyan -NoNewline
    Write-Host "[$Host_]" -ForegroundColor DarkGray -NoNewline
    Write-Host ": " -ForegroundColor White -NoNewline
    $Input_ = Read-Host
    if ($Input_) { $Host_ = $Input_ }

    Write-Host "  Listen port " -ForegroundColor Cyan -NoNewline
    Write-Host "[$Port]" -ForegroundColor DarkGray -NoNewline
    Write-Host ": " -ForegroundColor White -NoNewline
    $Input_ = Read-Host
    if ($Input_) { $Port = [int]$Input_ }

    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Encryption Key" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Enter a base64 AES-256-GCM key." -ForegroundColor White
    Write-Host "  Agents must use the same key to communicate." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Leave blank to auto-derive from:" -ForegroundColor DarkGray

    $Callback = "${Proto}://${Host_}:${Port}/api/v1/beacon"
    Write-Host "  SHA256(${Callback}:)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Key " -ForegroundColor Yellow -NoNewline
    Write-Host "(base64 or Enter to derive)" -ForegroundColor DarkGray -NoNewline
    Write-Host ": " -ForegroundColor White -NoNewline
    $Input_ = Read-Host
    if ($Input_) { $Key = $Input_ }

    Write-Host ""
    Write-Host "  Operator token " -ForegroundColor Cyan -NoNewline
    Write-Host "[random]" -ForegroundColor DarkGray -NoNewline
    Write-Host ": " -ForegroundColor White -NoNewline
    $Input_ = Read-Host
    if ($Input_) { $Token = $Input_ }

    Write-Host ""
}

# -- Generate token if not set --
if (-not $Token) {
    $Token = & $Python -c "import secrets; print(secrets.token_urlsafe(24))" 2>$null
    if (-not $Token) {
        $bytes = New-Object byte[] 24
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        $Token = [Convert]::ToBase64String($bytes) -replace '[=/+]',''
        $Token = $Token.Substring(0, [Math]::Min(32, $Token.Length))
    }
}

# -- Compute the actual encryption key for display --
if ($Key) {
    $EncKeyB64 = $Key
    $KeyType = "explicit (AES-256-GCM)"
    $KeyColor = "Green"
} elseif ($DeriveKey) {
    $PyCode = "import hashlib, base64; k = hashlib.sha256('$DeriveKey'.encode()).digest(); print(base64.b64encode(k).decode())"
    $EncKeyB64 = & $Python -c $PyCode
    $KeyType = "derived from --derive-key"
    $KeyColor = "Green"
} else {
    $PyCode = "import hashlib, base64; k = hashlib.sha256(':'.encode()).digest(); print(base64.b64encode(k).decode())"
    $EncKeyB64 = & $Python -c $PyCode
    $KeyType = 'DEFAULT -- SHA256(":")'
    $KeyColor = "Red"
}

$EncKeyB64 = $EncKeyB64.Trim()

# -- Display config --
Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
Write-Host "  │  Server Configuration                                │" -ForegroundColor DarkGray
Write-Host "  ├──────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
Write-Host "  │                                                      │" -ForegroundColor DarkGray

$ListenStr = "${Proto}://${Host_}:${Port}"
$GuiStr = "${Proto}://localhost:${Port}"
Write-Host "  │" -ForegroundColor DarkGray -NoNewline
Write-Host "  Listen       " -ForegroundColor Cyan -NoNewline
Write-Host $ListenStr.PadRight(38) -ForegroundColor White -NoNewline
Write-Host "│" -ForegroundColor DarkGray
Write-Host "  │" -ForegroundColor DarkGray -NoNewline
Write-Host "  GUI          " -ForegroundColor Cyan -NoNewline
Write-Host $GuiStr.PadRight(38) -ForegroundColor White -NoNewline
Write-Host "│" -ForegroundColor DarkGray
Write-Host "  │" -ForegroundColor DarkGray -NoNewline
Write-Host "  Encryption   " -ForegroundColor Cyan -NoNewline
Write-Host $KeyType.PadRight(38) -ForegroundColor $KeyColor -NoNewline
Write-Host "│" -ForegroundColor DarkGray

Write-Host "  │                                                      │" -ForegroundColor DarkGray
Write-Host "  ├──────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
Write-Host "  │" -ForegroundColor DarkGray -NoNewline
Write-Host "  Operator Token (for GUI login):                      " -ForegroundColor Yellow -NoNewline
Write-Host "│" -ForegroundColor DarkGray
Write-Host "  │                                                      │" -ForegroundColor DarkGray
Write-Host "  │" -ForegroundColor DarkGray -NoNewline
Write-Host "  $($Token.PadRight(52))" -ForegroundColor Green -NoNewline
Write-Host "│" -ForegroundColor DarkGray
Write-Host "  │                                                      │" -ForegroundColor DarkGray
Write-Host "  ├──────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
Write-Host "  │" -ForegroundColor DarkGray -NoNewline
Write-Host "  Encryption Key (for agent registration):             " -ForegroundColor Yellow -NoNewline
Write-Host "│" -ForegroundColor DarkGray
Write-Host "  │                                                      │" -ForegroundColor DarkGray
Write-Host "  │" -ForegroundColor DarkGray -NoNewline
Write-Host "  $($EncKeyB64.PadRight(52))" -ForegroundColor Cyan -NoNewline
Write-Host "│" -ForegroundColor DarkGray
Write-Host "  │                                                      │" -ForegroundColor DarkGray
Write-Host "  └──────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Press Ctrl+C to stop the server" -ForegroundColor DarkGray
Write-Host ""

# -- Build command --
$PyArgs = @($ServerPy, "--host", $Host_, "--port", $Port, "--token", $Token)
if ($Key)      { $PyArgs += "--key", $Key }
if ($DeriveKey){ $PyArgs += "--derive-key", $DeriveKey }
if ($SSL)      { $PyArgs += "--ssl" }
if ($Cert)     { $PyArgs += "--cert", $Cert }
if ($CertKey)  { $PyArgs += "--certkey", $CertKey }

# -- Launch --
& $Python @PyArgs
