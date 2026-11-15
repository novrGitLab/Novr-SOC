<#
.SYNOPSIS
  Stops the NovrSOC V2 local preview started by Start-NovrSOC.ps1.
.PARAMETER Database
  Also stops the disposable PostgreSQL container. Its data (tmpfs) is destroyed.
#>
[CmdletBinding()]
param([switch]$Database)

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Run = Join-Path $Root '.run'
foreach ($name in @('web', 'nhai', 'jobs', 'api', 'bridge')) {
    $pidFile = Join-Path $Run "$name.pid"
    if (Test-Path $pidFile) {
        $procId = (Get-Content -LiteralPath $pidFile -Raw).Trim()
        if ($procId) { & taskkill.exe /PID $procId /T /F *> $null }
        Remove-Item -LiteralPath $pidFile -Force
        Write-Host "stopped $name (process tree $procId)"
    }
}
if ($Database) {
    & docker compose -f (Join-Path $Root 'deploy\dev\compose.yaml') --env-file (Join-Path $Root 'deploy\dev\.env') down
    Write-Host 'stopped the disposable database (its data is gone)'
}
