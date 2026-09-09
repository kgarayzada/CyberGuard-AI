param([switch]$NoBrowser)
. (Join-Path $PSScriptRoot 'scripts\common.ps1')
Push-Location -LiteralPath $ProjectRoot
try {
    Write-Host 'Restoring the clean CyberGuard presentation dataset...' -ForegroundColor Cyan
    Stop-ProjectServices
    Assert-PortAvailable 8000
    Assert-PortAvailable 5173
    if (-not (Test-Path -LiteralPath $ProjectPython)) { throw 'Run .\start.ps1 once to create the project environment.' }
    & $ProjectPython -m backend.main --reset
    if ($LASTEXITCODE -ne 0) { throw 'Database reset did not complete.' }
    Write-Host 'Restored: score 58, 10 open findings, 1 resolved finding, 4 assessments.' -ForegroundColor Green
    & (Join-Path $ProjectRoot 'start.ps1') -NoBrowser:$NoBrowser
} catch { Write-Host "Reset could not finish safely: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
finally { Pop-Location }
