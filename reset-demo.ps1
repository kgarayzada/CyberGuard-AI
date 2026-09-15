param([switch]$NoBrowser)
. (Join-Path $PSScriptRoot 'scripts\common.ps1')
Push-Location -LiteralPath $ProjectRoot
try {
    Stop-ProjectServices
    Assert-PortAvailable 8000
    Assert-PortAvailable 5173
    if (Test-Path -LiteralPath $ProjectPython) {
        & $ProjectPython -m backend.main --reset
        if ($LASTEXITCODE -ne 0) { throw 'Database reset did not complete.' }
    } else { throw 'Run start.ps1 once to prepare the local Python environment.' }
    Write-Host 'Clean state ready: zero assessments, zero findings. Demo ZIP preserved. Run .\start.ps1.' -ForegroundColor Green
} catch { Write-Host "Reset could not finish safely: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
finally { Pop-Location }
