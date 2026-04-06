param(
    [string]$Inbox = "datasets",
    [string]$ReportsDir = "reports/auto",
    [string]$SqlitePath,
    [switch]$NoToolSetup,
    [switch]$NoAutoInstallTools,
    [switch]$RequireExternalTools
)

$projectRoot = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = $projectRoot

if (-not $NoToolSetup) {
    $checkToolsScript = Join-Path $PSScriptRoot "check_external_tools.ps1"
    $toolArgs = @{}
    if (-not $NoAutoInstallTools) {
        $toolArgs["InstallMissing"] = $true
    }
    if ($RequireExternalTools) {
        $toolArgs["Strict"] = $true
        $global:LASTEXITCODE = 0
    }

    & $checkToolsScript @toolArgs
    if ($RequireExternalTools -and $LASTEXITCODE -ne 0) {
        throw "External tools check failed. Install ffprobe/exiftool or run without -RequireExternalTools."
    }
}

New-Item -ItemType Directory -Force -Path $ReportsDir | Out-Null
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$jsonOut = Join-Path $ReportsDir "scan_$timestamp.json"

$arguments = @("-m", "media_security.cli", $Inbox, "--recursive", "--json-out", $jsonOut, "--no-tool-setup")
if ($SqlitePath) {
    $arguments += @("--sqlite-path", $SqlitePath)
}

python $arguments
