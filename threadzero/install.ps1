# THREADZERO installer for Windows 10/11 (PowerShell).   Usage:  powershell -ExecutionPolicy Bypass -File .\install.ps1
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Need($cmd, $hint) { if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { Write-Host "x missing: $cmd - $hint" -ForegroundColor Red; return $true }; return $false }
$missing = $false
$missing = (Need 'python' 'winget install Python.Python.3.12') -or $missing
$missing = (Need 'node'   'winget install OpenJS.NodeJS.LTS') -or $missing
$missing = (Need 'ghc'    'install GHCup: Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Command -ScriptBlock ([ScriptBlock]::Create((Invoke-WebRequest https://www.haskell.org/ghcup/sh/bootstrap-haskell.ps1 -UseBasicParsing))) -ArgumentList $true') -or $missing
if ($missing) { exit 1 }

Write-Host '> Python dependencies'
python -m pip install -r requirements.txt
python -m pip install -e .

Write-Host '> Haskell core'
New-Item -ItemType Directory -Force haskell\build | Out-Null
ghc -O1 -ihaskell/src -ihaskell/app -outputdir haskell/build -o haskell/build/threadzero-core.exe haskell/app/Main.hs

Write-Host '> Web studio'
Push-Location web
npm install
npm run build
Pop-Location

Write-Host '> Verifying'
python -m threadzero doctor
Write-Host ''
Write-Host 'Done. Start the studio with:  threadzero serve   (then open http://127.0.0.1:8737)' -ForegroundColor Green
