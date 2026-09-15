param([switch]$NoBrowser)
. (Join-Path $PSScriptRoot 'scripts\common.ps1')
Push-Location -LiteralPath $ProjectRoot
try {
    Write-Host "`nCYBERGUARD AI | Static source-code assessment" -ForegroundColor Cyan
    $backendReady = Test-ProjectService 'http://127.0.0.1:8000/api/health' 'cyberguard-ai'
    $frontendReady = Test-ProjectService 'http://127.0.0.1:5173/__cyberguard' 'cyberguard-frontend'
    if (-not $backendReady) { Assert-PortAvailable 8000 }
    if (-not $frontendReady) { Assert-PortAvailable 5173 }
    if (-not ($backendReady -and $frontendReady)) {
        $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
        $npmCommand = Get-Command npm.cmd -ErrorAction SilentlyContinue
        if (-not $nodeCommand -or -not $npmCommand) { throw 'Node.js and npm are required. Install them yourself, then rerun start.ps1. No system software was changed.' }
        $nodeVersion = & $nodeCommand.Source -p 'process.versions.node'
        $nodeParts = $nodeVersion.Split('.')
        if ([int]$nodeParts[0] -lt 22 -or ([int]$nodeParts[0] -eq 22 -and [int]$nodeParts[1] -lt 12)) { throw 'Node.js 22.12+ is required (Node 24 recommended). No system software was changed.' }
        New-Item -ItemType Directory -Force -Path (Join-Path $ProjectRoot 'data') | Out-Null
        if (-not (Test-Path -LiteralPath $ProjectPython)) {
            $launcher = Get-Command py -ErrorAction SilentlyContinue
            if ($launcher) { & $launcher.Source -3 -m venv (Join-Path $ProjectRoot '.venv') }
            else {
                $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
                if (-not $pythonCommand) { throw 'Python 3.10+ is required. Install Python yourself, then rerun start.ps1.' }
                & $pythonCommand.Source -m venv (Join-Path $ProjectRoot '.venv')
            }
            if ($LASTEXITCODE -ne 0) { throw 'Could not create .venv. Verify that a working Python 3.10+ runtime is available.' }
        }
        & $ProjectPython (Join-Path $ProjectRoot 'scripts\check-python.py')
        if ($LASTEXITCODE -ne 0) {
            Write-Host 'Installing Python dependencies into .venv...'
            & $ProjectPython -m pip install --no-cache-dir -r (Join-Path $ProjectRoot 'backend\requirements.txt')
            if ($LASTEXITCODE -ne 0) { throw 'Python dependency installation failed. Internet access is needed for first-time setup only.' }
        }
        $frontendDirectory = Join-Path $ProjectRoot 'frontend'
        if (-not (Test-Path -LiteralPath (Join-Path $frontendDirectory 'node_modules\vite\package.json'))) {
            Write-Host 'Installing local frontend dependencies...'
            Push-Location -LiteralPath $frontendDirectory
            try {
                & $npmCommand.Source ci --cache (Join-Path $ProjectRoot '.tooling\npm-cache') --no-audit --no-fund
                if ($LASTEXITCODE -ne 0) { throw 'Frontend installation failed. Internet access is needed for first-time setup only.' }
            } finally { Pop-Location }
        }
        if (-not $frontendReady) {
            $distFile = Join-Path $frontendDirectory 'dist\index.html'
            $needsBuild = -not (Test-Path -LiteralPath $distFile)
            if (-not $needsBuild) {
                $built = (Get-Item -LiteralPath $distFile).LastWriteTimeUtc
                $sourceFiles = @(Get-ChildItem -LiteralPath (Join-Path $frontendDirectory 'src'),(Join-Path $frontendDirectory 'public') -File -Recurse)
                $sourceFiles += Get-Item -LiteralPath (Join-Path $frontendDirectory 'package-lock.json'),(Join-Path $frontendDirectory 'index.html'),(Join-Path $frontendDirectory 'vite.config.ts'),(Join-Path $frontendDirectory 'tsconfig.json')
                $needsBuild = @($sourceFiles | Where-Object { $_.LastWriteTimeUtc -gt $built }).Count -gt 0
            }
            if ($needsBuild) {
                Write-Host 'Building the security assessment frontend...'
                Push-Location -LiteralPath $frontendDirectory
                try { & $npmCommand.Source run build; if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed. Check the message above.' } } finally { Pop-Location }
            }
        }
        if (-not $backendReady) {
            & (Join-Path $ProjectRoot 'scripts\setup-tools.ps1')
            & $ProjectPython (Join-Path $ProjectRoot 'scripts\check-tools.py')
            & $ProjectPython -m backend.main
            if ($LASTEXITCODE -ne 0) { throw 'Database initialization failed.' }
            $backendScript = Join-Path $ProjectRoot 'backend\serve.py'
            $backendProcess = Start-Process -FilePath $ProjectPython -ArgumentList @('"' + $backendScript + '"') -WorkingDirectory $ProjectRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $ProjectRoot 'data\backend.log') -RedirectStandardError (Join-Path $ProjectRoot 'data\backend-error.log') -PassThru
            Save-ProjectProcess $backendProcess $backendScript 'backend'
            Wait-ProjectService 'http://127.0.0.1:8000/api/health' 'cyberguard-ai'
        }
        if (-not $frontendReady) {
            $frontendScript = Join-Path $ProjectRoot 'scripts\serve-frontend.mjs'
            $frontendProcess = Start-Process -FilePath $nodeCommand.Source -ArgumentList @('"' + $frontendScript + '"') -WorkingDirectory $ProjectRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $ProjectRoot 'data\frontend.log') -RedirectStandardError (Join-Path $ProjectRoot 'data\frontend-error.log') -PassThru
            Save-ProjectProcess $frontendProcess $frontendScript 'frontend'
            Wait-ProjectService 'http://127.0.0.1:5173/__cyberguard' 'cyberguard-frontend'
        }
    }
    Write-Host "`nFrontend: http://127.0.0.1:5173" -ForegroundColor Green
    Write-Host 'API:      http://127.0.0.1:8000/api/health'
    Write-Host 'Reset:    .\reset-demo.ps1'
    Write-Host "Stop:     .\stop.ps1`n"
    if (-not $NoBrowser) { Start-Process 'http://127.0.0.1:5173' }
} catch {
    Write-Host "`nStartup could not finish: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} finally { Pop-Location }


