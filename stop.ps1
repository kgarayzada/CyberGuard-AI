. (Join-Path $PSScriptRoot 'scripts\common.ps1')
try { Stop-ProjectServices; Write-Host 'CyberGuard project services stopped. Your assessment data is preserved.' -ForegroundColor Green }
catch { Write-Host "Could not stop safely: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
