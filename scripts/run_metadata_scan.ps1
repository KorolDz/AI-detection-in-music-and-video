param(
    [Parameter(Mandatory = $true)]
    [string]$Target,
    [switch]$Recursive,
    [string]$JsonOut = "reports/metadata_scan_report.json",
    [string]$SqlitePath,
    [switch]$NoHistory,
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
        throw "External tools check failed. Install ffmpeg/ffprobe/exiftool or run without -RequireExternalTools."
    }
}

$arguments = @("-m", "media_security.cli", $Target, "--json-out", $JsonOut, "--no-tool-setup")
if ($Recursive) {
    $arguments += "--recursive"
}
if ($NoHistory) {
    $arguments += "--no-history"
}
elseif ($SqlitePath) {
    $arguments += @("--sqlite-path", $SqlitePath)
}

python $arguments
