<#
.SYNOPSIS
    Raccoon C2 Team Server — Launcher (Windows)
.DESCRIPTION
    Starts the Raccoon C2 team server with colored ASCII banner,
    pre-flight checks, and operator token display.
.EXAMPLE
    .\start_server.ps1
    .\start_server.ps1 -Port 443 -SSL
    .\start_server.ps1 -Key "base64key==" -Token "my-secret-token"
    .\start_server.ps1 -DeriveKey "https://c2.example.com/api/v1/beacon:c2.example.com"
#>
param(
    [int]$Port = 8443,
    [string]$Host_ = "0.0.0.0",
    [string]$Key = "",
    [string]$DeriveKey = "",
    [string]$Token = "",
    [switch]$SSL,
    [string]$Cert = "",
    [string]$CertKey = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ServerPy = Join-Path $ScriptDir "server.py"

# ── Generate token if not set ──
if (-not $Token) {
    $Token = python -c "import secrets; print(secrets.token_urlsafe(24))" 2>$null
    if (-not $Token) {
        $bytes = New-Object byte[] 24
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        $Token = [Convert]::ToBase64String($bytes) -replace '[=/+]','' | Select-Object -First 1
        $Token = $Token.Substring(0, [Math]::Min(32, $Token.Length))
    }
}

# ── Banner ──
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

# ── Pre-flight checks ──
$Python = $null
foreach ($cmd in @("python", "python3")) {
    try {
        $p = Get-Command $cmd -ErrorAction Stop
        $Python = $p.Source
        break
    } catch {}
}

if (-not $Python) {
    Write-Host "  [✗] " -ForegroundColor Red -NoNewline
    Write-Host "Python not found" -ForegroundColor White
    exit 1
}

$PyVer = & $Python --version 2>&1
Write-Host "  [✓] " -ForegroundColor Green -NoNewline
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
Write-Host "  [✓] " -ForegroundColor Green -NoNewline
Write-Host "Flask         " -ForegroundColor White -NoNewline
Write-Host "$FlaskVer" -ForegroundColor DarkGray
Write-Host "  [✓] " -ForegroundColor Green -NoNewline
Write-Host "Cryptography  " -ForegroundColor White -NoNewline
Write-Host "$CryptoVer" -ForegroundColor DarkGray

# ── Key info ──
$KeyType = "DEFAULT (insecure!)"
$KeyColor = "Red"
if ($Key) { $KeyType = "explicit (AES-256-GCM)"; $KeyColor = "Green" }
if ($DeriveKey) { $KeyType = "derived from callback:domain"; $KeyColor = "Green" }

$Proto = "http"
if ($SSL) { $Proto = "https" }

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
Write-Host "  │" -ForegroundColor DarkGray -NoNewline
Write-Host "  Server Configuration                                 " -ForegroundColor White -NoNewline
Write-Host "│" -ForegroundColor DarkGray
Write-Host "  ├──────────────────────────────────────────────────────┤" -ForegroundColor DarkGray

Write-Host "  │" -ForegroundColor DarkGray -NoNewline
Write-Host "                                                      " -NoNewline
Write-Host "│" -ForegroundColor DarkGray

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

Write-Host "  │" -ForegroundColor DarkGray -NoNewline
Write-Host "                                                      " -NoNewline
Write-Host "│" -ForegroundColor DarkGray
Write-Host "  ├──────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
Write-Host "  │" -ForegroundColor DarkGray -NoNewline
Write-Host "  Operator Token (for GUI access):                     " -ForegroundColor Yellow -NoNewline
Write-Host "│" -ForegroundColor DarkGray
Write-Host "  │" -ForegroundColor DarkGray -NoNewline
Write-Host "                                                      " -NoNewline
Write-Host "│" -ForegroundColor DarkGray
Write-Host "  │" -ForegroundColor DarkGray -NoNewline
Write-Host "  $($Token.PadRight(52))" -ForegroundColor Green -NoNewline
Write-Host "│" -ForegroundColor DarkGray
Write-Host "  │" -ForegroundColor DarkGray -NoNewline
Write-Host "                                                      " -NoNewline
Write-Host "│" -ForegroundColor DarkGray

Write-Host "  ├──────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
Write-Host "  │" -ForegroundColor DarkGray -NoNewline
Write-Host "  Beacon registration key derivation:                  " -ForegroundColor Yellow -NoNewline
Write-Host "│" -ForegroundColor DarkGray
Write-Host "  │" -ForegroundColor DarkGray -NoNewline
Write-Host "                                                      " -NoNewline
Write-Host "│" -ForegroundColor DarkGray

if ($Key) {
    $Display = "--key " + $Key.Substring(0, [Math]::Min(20, $Key.Length)) + "..."
    Write-Host "  │" -ForegroundColor DarkGray -NoNewline
    Write-Host "  $($Display.PadRight(52))" -ForegroundColor White -NoNewline
    Write-Host "│" -ForegroundColor DarkGray
} elseif ($DeriveKey) {
    $Display = "--derive-key " + $DeriveKey.Substring(0, [Math]::Min(24, $DeriveKey.Length)) + "..."
    Write-Host "  │" -ForegroundColor DarkGray -NoNewline
    Write-Host "  $($Display.PadRight(52))" -ForegroundColor White -NoNewline
    Write-Host "│" -ForegroundColor DarkGray
} else {
    Write-Host "  │" -ForegroundColor DarkGray -NoNewline
    Write-Host '  ⚠  No key set — using SHA256(":")                  ' -ForegroundColor Red -NoNewline
    Write-Host "│" -ForegroundColor DarkGray
    Write-Host "  │" -ForegroundColor DarkGray -NoNewline
    Write-Host "    Use -Key <b64> or -DeriveKey <str>                " -ForegroundColor DarkGray -NoNewline
    Write-Host "│" -ForegroundColor DarkGray
}

Write-Host "  │" -ForegroundColor DarkGray -NoNewline
Write-Host "                                                      " -NoNewline
Write-Host "│" -ForegroundColor DarkGray
Write-Host "  └──────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Press Ctrl+C to stop the server" -ForegroundColor DarkGray
Write-Host ""

# ── Build command ──
$Args = @($ServerPy, "--host", $Host_, "--port", $Port, "--token", $Token)
if ($Key)      { $Args += "--key", $Key }
if ($DeriveKey){ $Args += "--derive-key", $DeriveKey }
if ($SSL)      { $Args += "--ssl" }
if ($Cert)     { $Args += "--cert", $Cert }
if ($CertKey)  { $Args += "--certkey", $CertKey }

# ── Launch ──
& $Python @Args
