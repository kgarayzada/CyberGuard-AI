$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)
$RuntimePath = Join-Path $ProjectRoot 'data\runtime.json'
$ProjectPython = Join-Path $ProjectRoot '.venv\Scripts\python.exe'

function Test-ProjectService([string]$Url, [string]$Service) {
    try {
        $reply = Invoke-RestMethod -Uri $Url -TimeoutSec 2
        return ($reply.service -eq $Service -and $reply.workspace -eq $ProjectRoot)
    } catch { return $false }
}

function Assert-PortAvailable([int]$Port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $result = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        if ($result.AsyncWaitHandle.WaitOne(500) -and $client.Connected) {
            throw "Port $Port is occupied by another service. CyberGuard will not stop it. Close that service and rerun start.ps1."
        }
    } finally { $client.Dispose() }
}

function Wait-ProjectService([string]$Url, [string]$Service) {
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        if (Test-ProjectService $Url $Service) { return }
        Start-Sleep -Milliseconds 400
    }
    throw "The $Service service did not become ready. See project data/*.log for startup details."
}

function Save-ProjectProcess($Process, [string]$Script, [string]$Kind) {
    $records = @()
    if (Test-Path -LiteralPath $RuntimePath) {
        $existing = Get-Content -LiteralPath $RuntimePath -Raw | ConvertFrom-Json
        foreach ($item in $existing) { if ($item.kind -ne $Kind) { $records += $item } }
    }
    $Process.Refresh()
    $records += [PSCustomObject]@{ pid = $Process.Id; started = $Process.StartTime.ToUniversalTime().Ticks.ToString(); script = $Script; kind = $Kind }
    ConvertTo-Json -InputObject @($records) | Set-Content -LiteralPath $RuntimePath -Encoding UTF8
}

function Stop-ProjectServices {
    if (-not (Test-Path -LiteralPath $RuntimePath)) { return }
    $records = Get-Content -LiteralPath $RuntimePath -Raw | ConvertFrom-Json
    foreach ($record in $records) {
        $process = Get-Process -Id $record.pid -ErrorAction SilentlyContinue
        if (-not $process) { continue }
        if ($process.StartTime.ToUniversalTime().Ticks.ToString() -ne $record.started) { continue }
        $expectedScript = if ($record.kind -eq 'backend') { Join-Path $ProjectRoot 'backend\serve.py' } elseif ($record.kind -eq 'frontend') { Join-Path $ProjectRoot 'scripts\serve-frontend.mjs' } else { throw 'Unknown process record; refusing to stop it.' }
        if ($record.script -ne $expectedScript) { throw 'Process ownership mismatch; refusing to stop it.' }
        $details = Get-CimInstance Win32_Process -Filter "ProcessId = $($record.pid)"
        if (-not $details.CommandLine -or -not $details.CommandLine.Contains($expectedScript)) { throw 'Cannot verify the project process command line; refusing to stop it.' }
        Stop-Process -Id $record.pid -ErrorAction Stop
        Wait-Process -Id $record.pid -Timeout 10 -ErrorAction SilentlyContinue
    }
    # Only this known metadata file is removed. No process-name or port-wide killing.
    Remove-Item -LiteralPath $RuntimePath -Force
}
