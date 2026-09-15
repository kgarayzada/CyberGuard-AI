param([switch]$Retry)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$python=Join-Path $root '.venv\Scripts\python.exe'
$toolRoot=Join-Path $root '.tooling'
New-Item -ItemType Directory -Force -Path $toolRoot | Out-Null
$marker=Join-Path $toolRoot 'setup-attempted'
if ((Test-Path -LiteralPath $marker) -and -not $Retry) { return }
if (-not (Test-Path -LiteralPath $python)) { throw 'Run start.ps1 first to create the local Python environment.' }
try {
    if (-not (Test-Path -LiteralPath (Join-Path $root '.venv\Scripts\semgrep.exe'))) {
        & $python -m pip install --no-cache-dir 'semgrep==1.177.0'
        if ($LASTEXITCODE -ne 0) { Write-Warning 'Semgrep provisioning failed; unavailable status will be shown.' }
    }
    $destination=Join-Path $toolRoot 'gitleaks'
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    if (-not (Test-Path -LiteralPath (Join-Path $destination 'gitleaks.exe'))) {
        $version='8.30.0'
        $asset="gitleaks_${version}_windows_x64.zip"
        $base="https://github.com/gitleaks/gitleaks/releases/download/v$version"
        $zip=Join-Path $destination 'download.zip'
        $checks=Join-Path $destination 'checksums.txt'
        Invoke-WebRequest "$base/$asset" -OutFile $zip -UseBasicParsing -TimeoutSec 90
        Invoke-WebRequest "$base/gitleaks_${version}_checksums.txt" -OutFile $checks -UseBasicParsing -TimeoutSec 30
        $match=Get-Content -LiteralPath $checks | Where-Object { $_ -match ([regex]::Escape($asset)+'$') }
        if (-not $match) { throw 'Checksum entry missing.' }
        $expected=($match -split '\s+')[0]
        if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ne $expected) { throw 'Gitleaks checksum mismatch.' }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive=[IO.Compression.ZipFile]::OpenRead($zip)
        try {
            $entry=$archive.GetEntry('gitleaks.exe')
            if (-not $entry) { throw 'Scanner binary missing from release archive.' }
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry,(Join-Path $destination 'gitleaks.exe'),$true)
        } finally { $archive.Dispose() }
        Remove-Item -LiteralPath $zip
        Write-Host 'Project-local Gitleaks ready; SHA-256 verified against release checksums.'
    }
} catch { Write-Warning "Scanner setup could not finish: $($_.Exception.Message). Retry with .\scripts\setup-tools.ps1 -Retry" }
finally { Set-Content -LiteralPath $marker -Value 'Setup attempted. Use -Retry to try again.' }
