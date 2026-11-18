<#
.SYNOPSIS
  Starts the NovrSOC V2 local preview: disposable PostgreSQL -> FastAPI -> Next.js. Local only.

.DESCRIPTION
  Everything binds to 127.0.0.1 (never to a public interface):
    PostgreSQL  127.0.0.1:55432  (Docker, tmpfs: data is destroyed when the container stops)
    API         http://127.0.0.1:8000   (docs: /api/docs)
    Web         http://127.0.0.1:3210  (change with -WebPort)
  Steps: prerequisites -> port checks -> local env files -> database -> API venv -> migrations ->
  seed (only when empty) -> API -> web. Each step stops with a clear message if it fails.
  No production system, Wazuh, scanner or model host is contacted.

.PARAMETER WazuhMode
  local_fixture (default for the preview): the labelled local Wazuh fixture, shown in the UI as local fixture
  data, never as live telemetry. unconfigured: no Wazuh data at all (what an installation without a Wazuh
  connection shows). There is no live mode in this release.

.PARAMETER Setup
  pilot (default): the full local pilot. Adds a loopback Server 1 response bridge with the SIMULATED adapter (nothing
  is executed), the NHAI worker with the labelled test adapter (not a language model), VMS scanning limited to local
  test targets, the Brand Protection test resolver, and seeds the synthetic demonstrations (scripts/dev/seed_demo.py).
  foundation: the Phase 4 preview only (no bridge, no workers, adapters unconfigured).

.PARAMETER NoDemo
  Pilot profile without seeding the demonstrations.

.PARAMETER Production
  Build and serve the production web bundle (next build + next start) instead of the dev server.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\dev\Start-NovrSOC.ps1
#>
[CmdletBinding()]
param([switch]$Production, [int]$WebPort = 3210,
      [ValidateSet('local_fixture', 'unconfigured')][string]$WazuhMode = 'local_fixture',
      [ValidateSet('pilot', 'foundation')][string]$Setup = 'pilot',
      [switch]$NoDemo)

$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Api = Join-Path $Root 'apps\api'
$Web = Join-Path $Root 'apps\web'
$Db = Join-Path $Root 'packages\db'
$Run = Join-Path $Root '.run'
$Compose = Join-Path $Root 'deploy\dev\compose.yaml'
$DevEnv = Join-Path $Root 'deploy\dev\.env'
$ApiEnv = Join-Path $Api '.env'
$Creds = Join-Path $env:LOCALAPPDATA 'NovrSOC\dev-credentials.json'
$Py = Join-Path $Api '.venv\Scripts\python.exe'

function Step([string]$m) { Write-Host "`n==> $m" -ForegroundColor Magenta }
function Fail([string]$m) { Write-Host "`nERROR: $m" -ForegroundColor Red; exit 1 }
function Test-Native([scriptblock]$cmd) {
    # Windows PowerShell 5.1 turns native stderr into a terminating error under 'Stop'; relax it for probes only.
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & $cmd *> $null; return ($LASTEXITCODE -eq 0) } finally { $ErrorActionPreference = $old }
}
function Test-Port([int]$port) {
    $c = New-Object System.Net.Sockets.TcpClient
    try { $iar = $c.BeginConnect('127.0.0.1', $port, $null, $null); return ($iar.AsyncWaitHandle.WaitOne(300) -and $c.Connected) }
    catch { return $false } finally { $c.Close() }
}
function Wait-Http([string]$url, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        try { $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 3; if ($r.StatusCode -lt 500) { return $true } } catch { }
        Start-Sleep -Milliseconds 700
    }
    return $false
}
function Read-EnvValue([string]$file, [string]$key) {
    foreach ($line in Get-Content -LiteralPath $file) { if ($line.StartsWith("$key=")) { return $line.Substring($key.Length + 1) } }
    return $null
}

Step 'Checking prerequisites'
foreach ($cmd in @('docker', 'py', 'node', 'npm.cmd')) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { Fail "'$cmd' was not found on PATH. Install it (see docs/public/LOCAL_DEVELOPMENT.md)." }
}
if (-not (Test-Native { docker info --format '{{.ServerVersion}}' })) { Fail 'Docker is installed but not running. Start Docker Desktop and try again.' }
if (-not (Test-Native { py -3.12 -c "import sys" })) { Fail 'Python 3.12 is required for the API (py -3.12). Install it from python.org.' }

Step 'Checking ports'
foreach ($p in @(8000, $WebPort)) {
    if (Test-Port $p) { Fail "Port $p is already in use. Run .\scripts\dev\Stop-NovrSOC.ps1, or stop whatever listens on 127.0.0.1:$p." }
}

Step 'Local environment files (random local passwords, git-ignored)'
if (-not ((Test-Path $DevEnv) -and (Test-Path $ApiEnv))) {
    & py -3.12 (Join-Path $Root 'scripts\dev\bootstrap_env.py')
    if ($LASTEXITCODE -ne 0) { Fail 'Could not write the local env files.' }
}

Step 'Disposable PostgreSQL (127.0.0.1:55432, tmpfs)'
$running = (& docker ps --filter 'name=^novrsoc-v2-dev-postgres$' --format '{{.Names}}')
if (-not $running -and (Test-Port 55432)) { Fail 'Port 55432 is used by something other than the NovrSOC dev database.' }
& docker compose -f $Compose --env-file $DevEnv up -d
if ($LASTEXITCODE -ne 0) { Fail 'docker compose could not start the database. See the output above.' }
$healthy = $false
for ($i = 0; $i -lt 60; $i++) {
    $h = (& docker inspect -f '{{.State.Health.Status}}' novrsoc-v2-dev-postgres)
    if ($h -eq 'healthy') { $healthy = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $healthy) { Fail 'The database did not become healthy within 60 s. Check: docker logs novrsoc-v2-dev-postgres' }

Step 'API environment (Python 3.12 venv)'
if (-not (Test-Path $Py)) {
    & py -3.12 -m venv (Join-Path $Api '.venv')
    & $Py -m pip install --disable-pip-version-check -q -r (Join-Path $Api 'requirements.lock')
    if ($LASTEXITCODE -ne 0) { Fail 'pip could not install the API dependencies.' }
}
if (-not (Test-Native { & $Py -c "import novrsoc_contracts" })) {
    & $Py -m pip install --disable-pip-version-check -q -e (Join-Path $Root 'packages\contracts')
    if ($LASTEXITCODE -ne 0) { Fail 'pip could not install packages/contracts.' }
}

Step 'Database migrations (Alembic, schema owner)'
$env:NOVRSOC_MIGRATION_DATABASE_URL = Read-EnvValue $ApiEnv 'NOVRSOC_MIGRATION_DATABASE_URL'
Push-Location $Db
try { & (Join-Path $Api '.venv\Scripts\alembic.exe') upgrade head } finally { Pop-Location }
if ($LASTEXITCODE -ne 0) { Fail 'Migrations failed. See the output above.' }

Step 'Disposable sample data (only if the database is empty)'
Push-Location $Api
try { & $Py -m app.cli seed-dev --if-empty --out $Creds } finally { Pop-Location }
$seedCode = $LASTEXITCODE
if ($seedCode -eq 0 -and $WazuhMode -eq 'local_fixture') {
    Step 'Local fixture data (Wazuh group mappings + fixture alerts, idempotent)'
    Push-Location $Api
    try { & $Py -m app.cli seed-dev-fixtures } finally { Pop-Location }
    $seedCode = $LASTEXITCODE
}
Remove-Item Env:\NOVRSOC_MIGRATION_DATABASE_URL -ErrorAction SilentlyContinue
if ($seedCode -ne 0) { Fail 'Seeding failed. See the output above.' }

Step 'Web dependencies'
if (-not (Test-Path (Join-Path $Web 'node_modules\next'))) {
    Push-Location $Web; try { & npm.cmd ci --no-audit --no-fund } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { Fail 'npm ci failed.' }
}

New-Item -ItemType Directory -Force $Run | Out-Null

$env:NOVRSOC_WAZUH_MODE = $WazuhMode
if ($Setup -eq 'pilot') {
    Step 'Pilot: local Server 1 response bridge (simulated adapter, loopback only)'
    $StateDir = Join-Path $env:LOCALAPPDATA 'NovrSOC'
    New-Item -ItemType Directory -Force $StateDir | Out-Null
    $BridgeKey = Join-Path $StateDir 'soar-bridge.key'
    if (-not (Test-Path $BridgeKey)) {
        $bytes = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        Set-Content -LiteralPath $BridgeKey -Value (($bytes | ForEach-Object { $_.ToString('x2') }) -join '') -NoNewline -Encoding ascii
    }
    $orgs = (Get-Content -LiteralPath $Creds -Raw | ConvertFrom-Json).orgs
    $bridgeCfg = @{ listen = '127.0.0.1'; port = 8650; keys = @{ 'server2-soar' = $BridgeKey }
        state_db = (Join-Path $Run 'bridge-receipts.sqlite3'); adapter = 'simulated'; allow_live = $false
        actions = @('block_ip', 'isolate_agent'); never_block = @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
        simulated_agents = @{ '001' = @('nv-alpha-servers'); '002' = @('nv-alpha-servers'); '003' = @('nv-alpha-workstations'); '004' = @('nv-beta-servers') }
        tenants = @{ $orgs.alpha = @{ actions = @('block_ip', 'isolate_agent'); agent_groups = @('nv-alpha-servers') } } }
    $BridgeCfgFile = Join-Path $Run 'bridge.json'
    ($bridgeCfg | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $BridgeCfgFile -Encoding ascii
    $bridgeProc = Start-Process -FilePath $Py -ArgumentList '-m', 'novrsoc_bridge', '--config', ('"' + $BridgeCfgFile + '"') `
        -WorkingDirectory (Join-Path $Root 'services\edge\response_bridge') -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $Run 'bridge.out.log') -RedirectStandardError (Join-Path $Run 'bridge.err.log')
    Set-Content -LiteralPath (Join-Path $Run 'bridge.pid') -Value $bridgeProc.Id -Encoding ascii
    if (-not (Wait-Http 'http://127.0.0.1:8650/v1/health' 30)) { Get-Content (Join-Path $Run 'bridge.err.log') -Tail 20; Fail 'The response bridge did not start.' }
    $env:NOVRSOC_SOAR_BRIDGE_URL = 'http://127.0.0.1:8650'
    $env:NOVRSOC_SOAR_BRIDGE_KEY_FILE = $BridgeKey
    $env:NOVRSOC_NHAI_BACKEND = 'test_adapter'
    $env:NOVRSOC_VMS_SCANNING = 'local_test_targets'
    $env:NOVRSOC_BRAND_RESOLVER = 'test_adapter'
}
# Organization portals in development: <name>.novrsoc.localhost:<web port> resolves to this machine in every browser. The
# local Next.js proxy forwards the browser's host (X-Forwarded-Host), which only this loopback API trusts. Agent
# enrollment stays disabled here (there is no NovrSIEM manager); the syslog address is a placeholder.
$env:NOVRSOC_PORTAL_BASE_DOMAIN = 'novrsoc.localhost'
$env:NOVRSOC_TRUST_FORWARDED_HOST = 'true'
$env:NOVRSOC_PUBLIC_SCHEME = 'http'
$env:NOVRSOC_PUBLIC_PORT = "$WebPort"
$env:NOVRSOC_PUBLIC_PLATFORM_HOST = 'localhost'
$env:NOVRSOC_AGENT_MANAGER_ADDRESS = 'siem.novrsoc.localhost'
$env:NOVRSOC_SYSLOG_COLLECTOR_ADDRESS = 'syslog.novrsoc.localhost'
Step 'Environment validation (python -m app.cli check-env)'
Push-Location $Api
try { & $Py -m app.cli check-env } finally { Pop-Location }
if ($LASTEXITCODE -ne 0) { Fail 'Environment validation failed. See the lines marked FAIL above.' }
Step "Starting the API on http://127.0.0.1:8000 (Wazuh data source: $WazuhMode, setup: $Setup)"
$apiProc = Start-Process -FilePath $Py -ArgumentList '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', '8000' `
    -WorkingDirectory $Api -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput (Join-Path $Run 'api.out.log') -RedirectStandardError (Join-Path $Run 'api.err.log')
Set-Content -LiteralPath (Join-Path $Run 'api.pid') -Value $apiProc.Id -Encoding ascii
if ($Setup -eq 'pilot') {
    $nhaiProc = Start-Process -FilePath $Py -ArgumentList '-m', 'app.nhai.worker' -WorkingDirectory $Api -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $Run 'nhai.out.log') -RedirectStandardError (Join-Path $Run 'nhai.err.log')
    Set-Content -LiteralPath (Join-Path $Run 'nhai.pid') -Value $nhaiProc.Id -Encoding ascii
}
# Background jobs worker (Server 2 component): SLA escalation, due schedules (only where scanning is enabled), CNII check
# bookkeeping, approval expiry. It never executes a response action.
$jobsProc = Start-Process -FilePath $Py -ArgumentList '-m', 'app.jobs' -WorkingDirectory $Api -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput (Join-Path $Run 'jobs.out.log') -RedirectStandardError (Join-Path $Run 'jobs.err.log')
Set-Content -LiteralPath (Join-Path $Run 'jobs.pid') -Value $jobsProc.Id -Encoding ascii
if (-not (Wait-Http 'http://127.0.0.1:8000/readyz' 45)) {
    Get-Content (Join-Path $Run 'api.err.log') -Tail 20
    Fail 'The API did not become ready (http://127.0.0.1:8000/readyz). The log tail is above.'
}

$env:NOVRSOC_API_ORIGIN = 'http://127.0.0.1:8000'
$env:NEXT_TELEMETRY_DISABLED = '1'
if ($Production) {
    Step 'Building the production web bundle'
    Push-Location $Web; try { & npm.cmd run build } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { Fail 'next build failed.' }
    $nextMode = 'start'
} else {
    $nextMode = 'dev'
}
$nextBin = Join-Path $Web 'node_modules/next/dist/bin/next'
$webArgs = @(('"' + $nextBin + '"'), $nextMode, '-H', '127.0.0.1', '-p', "$WebPort")
Step "Starting the web app on http://127.0.0.1:$WebPort"
$webProc = Start-Process -FilePath 'node.exe' -ArgumentList $webArgs -WorkingDirectory $Web -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput (Join-Path $Run 'web.out.log') -RedirectStandardError (Join-Path $Run 'web.err.log')
Set-Content -LiteralPath (Join-Path $Run 'web.pid') -Value $webProc.Id -Encoding ascii
if (-not (Wait-Http "http://127.0.0.1:$WebPort/login" 180)) {
    Get-Content (Join-Path $Run 'web.err.log') -Tail 20
    Fail "The web app did not start (http://127.0.0.1:$WebPort/login). The log tail is above."
}

$DemoSeeder = Join-Path $Root 'scripts\dev\seed_demo.py'
if ($Setup -eq 'pilot' -and -not $NoDemo -and -not (Test-Path $DemoSeeder)) {
    Write-Host "`nNo demo seeder (scripts/dev/seed_demo.py is not part of this checkout): starting without demonstrations." -ForegroundColor Yellow
} elseif ($Setup -eq 'pilot' -and -not $NoDemo) {
    Step 'Seeding the synthetic demonstrations through the API (scripts/dev/seed_demo.py)'
    & $Py $DemoSeeder --creds $Creds
    if ($LASTEXITCODE -ne 0) { Write-Host 'Demo seeding reported a problem (see above); the pilot is running.' -ForegroundColor Yellow }
}

Write-Host "`nNovrSOC V2 local $Setup is running (127.0.0.1 only)." -ForegroundColor Green
Write-Host "  Web        http://127.0.0.1:$WebPort"
Write-Host "  API docs   http://127.0.0.1:8000/api/docs"
Write-Host "  Readiness  http://127.0.0.1:8000/readyz"
Write-Host "  Sign-in accounts (disposable, random passwords): $Creds"
Write-Host "  Logs: $Run   Stop: .\scripts\dev\Stop-NovrSOC.ps1  (add -Database to destroy the dev database)"
