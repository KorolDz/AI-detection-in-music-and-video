param()

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$safeProjectRoot = (Resolve-Path -Path $projectRoot).Path.Replace("\", "/")
$hooksDir = Join-Path $projectRoot ".githooks"

if (-not (Test-Path -Path $hooksDir -PathType Container)) {
    throw "Hooks directory not found: $hooksDir"
}

if ($null -eq (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "Git is not available in PATH."
}

& git -c "safe.directory=$safeProjectRoot" -C $projectRoot config core.hooksPath .githooks
if ($LASTEXITCODE -ne 0) {
    throw "Unable to configure git hooks path."
}

Write-Host "Git hooks installed. core.hooksPath -> .githooks" -ForegroundColor Green
