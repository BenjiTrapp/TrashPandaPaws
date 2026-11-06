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
.NOTES
    -Host_/-Port are the beacon socket, reachable from the network.
    -OperatorHost/-OperatorPort are the GUI and API, loopback by default;
    an -OperatorPort equal to -Port serves both on one socket.
#>
param(
    [int]$Port = 8443,
    [string]$Host_ = "0.0.0.0",
    [int]$OperatorPort = 8444,
    [string]$OperatorHost = "127.0.0.1",
    [string]$Key = "",
    [string]$Token = "",
    [switch]$SSL,
    [string]$Cert = "",
    [string]$CertKey = "",
    [switch]$NoPrompt
)

$ErrorActionPreference = "Continue"
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

# -- Virtual environment --
$VenvDir = Join-Path $ScriptDir ".venv"
$VenvPython = Join-Path (Join-Path $VenvDir "Scripts") "python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host "  [*] " -ForegroundColor Cyan -NoNewline
    Write-Host "Creating venv " -ForegroundColor White -NoNewline
    Write-Host "$VenvDir" -ForegroundColor DarkGray
    & $Python -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [X] " -ForegroundColor Red -NoNewline
        Write-Host "Failed to create venv" -ForegroundColor White
        exit 1
    }
}

$Python = $VenvPython
Write-Host "  [+] " -ForegroundColor Green -NoNewline
Write-Host "Venv          " -ForegroundColor White -NoNewline
Write-Host "$VenvDir" -ForegroundColor DarkGray

# -- Ensure pip is available in venv --
& $Python -m ensurepip --upgrade 2>$null
& $Python -m pip install --upgrade pip --quiet 2>$null

# -- Dependencies (pip) --
$PipPkgs = @("flask", "cryptography", "impacket", "ldap3", "lsassy")

Write-Host "  [*] " -ForegroundColor Cyan -NoNewline
Write-Host "Checking deps " -ForegroundColor White -NoNewline
Write-Host ($PipPkgs -join ", ") -ForegroundColor DarkGray
foreach ($pkg in $PipPkgs) {
    $out = & $Python -m pip install $pkg --quiet 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [!] " -ForegroundColor Yellow -NoNewline
        Write-Host "$pkg install failed (skipped)" -ForegroundColor DarkGray
    }
}

# -- NetExec (pipx, installed from GitHub) --
$HasPipx = $null -ne (Get-Command pipx -ErrorAction SilentlyContinue)
$HasNxc = $null -ne (Get-Command nxc -ErrorAction SilentlyContinue)
if (-not $HasPipx) {
    Write-Host ""
    Write-Host "  [?] " -ForegroundColor Yellow -NoNewline
    Write-Host "pipx is required for NetExec. Install pipx now? " -ForegroundColor White -NoNewline
    Write-Host "[Y/n] " -ForegroundColor DarkGray -NoNewline
    $answer = Read-Host
    if ($answer -eq "" -or $answer -match "^[yYjJ]") {
        Write-Host "  [*] " -ForegroundColor Cyan -NoNewline
        Write-Host "Installing    " -ForegroundColor White -NoNewline
        Write-Host "pipx" -ForegroundColor DarkGray
        & $Python -m pip install pipx --quiet 2>$null
        & $Python -m pipx ensurepath 2>$null
        $HasPipx = $null -ne (Get-Command pipx -ErrorAction SilentlyContinue)
        if (-not $HasPipx) {
            $pipxBin = & $Python -c "import sysconfig; print(sysconfig.get_path('scripts'))" 2>$null
            if ($pipxBin -and (Test-Path (Join-Path $pipxBin "pipx.exe"))) {
                $env:PATH = "$pipxBin;$env:PATH"
                $HasPipx = $true
            }
        }
        if ($HasPipx) {
            Write-Host "  [+] " -ForegroundColor Green -NoNewline
            Write-Host "pipx          " -ForegroundColor White -NoNewline
            Write-Host "installed" -ForegroundColor DarkGray
        } else {
            Write-Host "  [!] " -ForegroundColor Yellow -NoNewline
            Write-Host "pipx          " -ForegroundColor White -NoNewline
            Write-Host "install failed" -ForegroundColor Yellow
        }
    }
}
if ($HasPipx -and -not $HasNxc) {
    Write-Host "  [*] " -ForegroundColor Cyan -NoNewline
    Write-Host "Installing    " -ForegroundColor White -NoNewline
    Write-Host "netexec (pipx)" -ForegroundColor DarkGray
    pipx install git+https://github.com/Pennyw0rth/NetExec 2>$null
    $pipxBinDir = Join-Path $env:USERPROFILE ".local\bin"
    if (-not (Get-Command nxc -ErrorAction SilentlyContinue)) {
        if (Test-Path (Join-Path $pipxBinDir "nxc.exe")) {
            $env:PATH = "$pipxBinDir;$env:PATH"
        }
    }
}

# -- Version display --
$AllDisplay = @(
    @("Flask",        "flask"),
    @("Cryptography", "cryptography"),
    @("Impacket",     "impacket"),
    @("ldap3",        "ldap3"),
    @("Lsassy",       "lsassy")
)
foreach ($entry in $AllDisplay) {
    $label = $entry[0].PadRight(14)
    $ver = & $Python -c "import importlib.metadata; print(importlib.metadata.version('$($entry[1])'))" 2>$null
    if (-not $ver) {
        Write-Host "  [!] " -ForegroundColor Yellow -NoNewline
        Write-Host $label -ForegroundColor White -NoNewline
        Write-Host "not installed" -ForegroundColor Yellow
    } else {
        Write-Host "  [+] " -ForegroundColor Green -NoNewline
        Write-Host $label -ForegroundColor White -NoNewline
        Write-Host $ver -ForegroundColor DarkGray
    }
}
$nxcVer = ""
$nxcCmd = Get-Command nxc -ErrorAction SilentlyContinue
if ($nxcCmd) { $nxcVer = & nxc --version 2>$null }
if ($nxcVer) {
    Write-Host "  [+] " -ForegroundColor Green -NoNewline
    Write-Host "NetExec       " -ForegroundColor White -NoNewline
    Write-Host "$nxcVer" -ForegroundColor DarkGray
} else {
    Write-Host "  [!] " -ForegroundColor Yellow -NoNewline
    Write-Host "NetExec       " -ForegroundColor White -NoNewline
    Write-Host "not installed (requires pipx)" -ForegroundColor Yellow
}

# -- Interactive configuration --
$Proto = "http"
if ($SSL) { $Proto = "https" }

$KeyOrigin = ""
if ($Key) { $KeyOrigin = "passed with -Key" }

if (-not $NoPrompt -and -not $Key) {
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Server Configuration" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  Beacon listen host " -ForegroundColor Cyan -NoNewline
    Write-Host "[$Host_]" -ForegroundColor DarkGray -NoNewline
    Write-Host ": " -ForegroundColor White -NoNewline
    $Input_ = Read-Host
    if ($Input_) { $Host_ = $Input_ }

    Write-Host "  Beacon listen port " -ForegroundColor Cyan -NoNewline
    Write-Host "[$Port]" -ForegroundColor DarkGray -NoNewline
    Write-Host ": " -ForegroundColor White -NoNewline
    $Input_ = Read-Host
    if ($Input_) { $Port = [int]$Input_ }

    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Encryption" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Use AES-256-GCM encryption for beacon comms?" -ForegroundColor White
    Write-Host "  Agents must use the same key to communicate." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [1] " -ForegroundColor Cyan -NoNewline
    Write-Host "Generate a random key (default)" -ForegroundColor White
    Write-Host "  [2] " -ForegroundColor Cyan -NoNewline
    Write-Host "Enter a key manually (base64)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Choice " -ForegroundColor Yellow -NoNewline
    Write-Host "[1]" -ForegroundColor DarkGray -NoNewline
    Write-Host ": " -ForegroundColor White -NoNewline
    $Input_ = Read-Host
    if (-not $Input_) { $Input_ = "1" }

    switch ($Input_) {
        "1" {
            $Key = & $Python -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
            $Key = $Key.Trim()
            Write-Host ""
            Write-Host "  [+] " -ForegroundColor Green -NoNewline
            Write-Host "Generated random AES-256-GCM key" -ForegroundColor White
            Write-Host "  $Key" -ForegroundColor Cyan
            Write-Host "  ! Save this key -- agents need it to connect!" -ForegroundColor Red
            $KeyOrigin = "generated for this run"
        }
        "2" {
            Write-Host ""
            Write-Host "  Key " -ForegroundColor Yellow -NoNewline
            Write-Host "(base64 AES-256-GCM, 32 bytes)" -ForegroundColor DarkGray -NoNewline
            Write-Host ": " -ForegroundColor White -NoNewline
            $Input_ = Read-Host
            if ($Input_) {
                $Key = $Input_
                $KeyOrigin = "entered by hand"
                Write-Host "  [+] " -ForegroundColor Green -NoNewline
                Write-Host "Using provided key" -ForegroundColor White
            }
        }
        default {
            Write-Host "  [x] " -ForegroundColor Red -NoNewline
            Write-Host "Choose 1 or 2" -ForegroundColor White
            exit 1
        }
    }

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

# -- The key is required: there is no default and none is derived --
if (-not $Key) {
    Write-Host "  [x] " -ForegroundColor Red -NoNewline
    Write-Host "No encryption key. The server will not start without one." -ForegroundColor White
    Write-Host "  Pass -Key <base64>, or run interactively and generate one:" -ForegroundColor DarkGray
    Write-Host '  python -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"' -ForegroundColor DarkGray
    exit 1
}
$EncKeyB64 = $Key
$KeyType = "$KeyOrigin (AES-256-GCM)"
$KeyColor = "Green"

$EncKeyB64 = $EncKeyB64.Trim()

# -- Display config --
Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
Write-Host "  │  Server Configuration                                │" -ForegroundColor DarkGray
Write-Host "  ├──────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
Write-Host "  │                                                      │" -ForegroundColor DarkGray

$ListenStr = "${Proto}://${Host_}:${Port}"
$GuiStr = "${Proto}://${OperatorHost}:${OperatorPort}"
Write-Host "  │" -ForegroundColor DarkGray -NoNewline
Write-Host "  Beacons      " -ForegroundColor Cyan -NoNewline
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
if ($OperatorPort -ne $Port -and ($OperatorHost -like "127.*" -or $OperatorHost -eq "localhost" -or $OperatorHost -eq "::1")) {
    Write-Host "  The GUI is loopback only. From another machine:" -ForegroundColor DarkGray
    Write-Host "  ssh -L ${OperatorPort}:${OperatorHost}:${OperatorPort} <user>@<this-host>, then open ${Proto}://localhost:${OperatorPort}" -ForegroundColor DarkGray
    Write-Host ""
}
Write-Host "  Press Ctrl+C to stop the server" -ForegroundColor DarkGray
Write-Host ""

# -- Build command --
$PyArgs = @($ServerPy, "--host", $Host_, "--port", $Port,
            "--operator-host", $OperatorHost, "--operator-port", $OperatorPort,
            "--token", $Token)
$PyArgs += "--key", $Key
if ($SSL)      { $PyArgs += "--ssl" }
if ($Cert)     { $PyArgs += "--cert", $Cert }
if ($CertKey)  { $PyArgs += "--certkey", $CertKey }

# -- Launch --
& $Python @PyArgs
