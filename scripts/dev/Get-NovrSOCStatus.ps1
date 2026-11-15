<#
.SYNOPSIS
  Shows whether each part of the NovrSOC V2 local preview is up, with the reason when it is not.
#>
param([int]$WebPort = 3210)
function Probe([string]$name, [string]$url) {
    try {
        $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 3
        Write-Host ("{0,-10} OK    {1} ({2})" -f $name, $url, $r.StatusCode) -ForegroundColor Green
    } catch {
        $code = $null
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        if ($code) { Write-Host ("{0,-10} DOWN  {1} (HTTP {2})" -f $name, $url, $code) -ForegroundColor Yellow }
        else { Write-Host ("{0,-10} DOWN  {1} (not listening)" -f $name, $url) -ForegroundColor Red }
    }
}
$db = (& docker inspect -f '{{.State.Health.Status}}' novrsoc-v2-dev-postgres 2>$null)
if ($db) { Write-Host ("{0,-10} {1}  container novrsoc-v2-dev-postgres (127.0.0.1:55432)" -f 'database', $db.ToUpper()) }
else { Write-Host ("{0,-10} DOWN  container not running" -f 'database') -ForegroundColor Red }
Probe 'api' 'http://127.0.0.1:8000/readyz'
Probe 'web' "http://127.0.0.1:$WebPort/login"
