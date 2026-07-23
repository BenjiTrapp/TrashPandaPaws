<#
.SYNOPSIS
    Raccoon C2 - Test Agent Registration
.DESCRIPTION
    Registers a test beacon agent with the C2 server.
    Prompts for the encryption key if not provided.
.EXAMPLE
    .\test_add_agent.ps1
    .\test_add_agent.ps1 -Host_ 192.168.1.100 -Port 443 -SSL
    .\test_add_agent.ps1 -Key "base64key=="
#>
param(
    [string]$Host_ = "127.0.0.1",
    [int]$Port = 8443,
    [string]$Key = "",
    [int]$Interval = 5,
    [int]$Jitter = 10,
    [switch]$SSL
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$AgentPy = Join-Path $ScriptDir "test_add_agent.py"

# -- Banner --
Clear-Host
Write-Host ""
Write-Host "    +================================================+" -ForegroundColor Red
Write-Host "    |" -ForegroundColor Red -NoNewline
Write-Host "  " -NoNewline
Write-Host "Raccoon C2 - Test Agent" -ForegroundColor White -NoNewline
Write-Host "                       " -NoNewline
Write-Host "|" -ForegroundColor Red
Write-Host "    +================================================+" -ForegroundColor Red
Write-Host ""

# -- Python check --
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
Write-Host "Python   " -ForegroundColor White -NoNewline
Write-Host "$PyVer" -ForegroundColor DarkGray

# -- Prompt for key if not set --
$Proto = "http"
if ($SSL) { $Proto = "https" }
$Callback = "${Proto}://${Host_}:${Port}/api/v1/beacon"

if (-not $Key) {
    Write-Host ""
    Write-Host "  ---------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Encryption Key" -ForegroundColor Yellow
    Write-Host "  ---------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Enter a base64 AES-256-GCM key." -ForegroundColor White
    Write-Host "  This must match the key the server was started with." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Leave blank to use server default:" -ForegroundColor DarkGray
    Write-Host "  SHA256("":"")" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Key " -ForegroundColor Yellow -NoNewline
    Write-Host "(base64 or Enter to derive)" -ForegroundColor DarkGray -NoNewline
    Write-Host ": " -ForegroundColor White -NoNewline
    $Key = Read-Host

    if (-not $Key) {
        $Key = & $Python -c "import hashlib, base64; k = hashlib.sha256(':'.encode()).digest(); print(base64.b64encode(k).decode())"
        Write-Host "  [+] " -ForegroundColor Green -NoNewline
        Write-Host "Using server default key: SHA256(':')" -ForegroundColor White
    } else {
        Write-Host "  [+] " -ForegroundColor Green -NoNewline
        Write-Host "Using explicit key" -ForegroundColor White
    }
}

# -- Display config --
$KeyPreview = $Key
if ($Key.Length -gt 24) { $KeyPreview = $Key.Substring(0, 24) + "..." }

Write-Host ""
Write-Host "  ---------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Agent Configuration" -ForegroundColor White
Write-Host "  ---------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Server     " -ForegroundColor Cyan -NoNewline
Write-Host "${Proto}://${Host_}:${Port}" -ForegroundColor White
Write-Host "  Interval   " -ForegroundColor Cyan -NoNewline
Write-Host "${Interval}s " -ForegroundColor White -NoNewline
Write-Host "(jitter ${Jitter}%)" -ForegroundColor DarkGray
Write-Host "  Key        " -ForegroundColor Cyan -NoNewline
Write-Host "$KeyPreview" -ForegroundColor White
Write-Host "  ---------------------------------------------" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  [>] " -ForegroundColor Green -NoNewline
Write-Host "Starting beacon..." -ForegroundColor White
Write-Host "  Press Ctrl+C to stop" -ForegroundColor DarkGray
Write-Host ""

# -- Launch --
Set-Location $RepoRoot

$PyArgs = @($AgentPy, "--host", $Host_, "--port", $Port, "--key", $Key, "--interval", $Interval, "--jitter", $Jitter)
if ($SSL) { $PyArgs += "--ssl" }

& $Python @PyArgs
