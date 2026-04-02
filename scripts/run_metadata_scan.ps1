param(
    [Parameter(Mandatory = $true)]
    [string]$Target,
    [switch]$Recursive,
    [string]$JsonOut = "reports/metadata_scan_report.json"
)

$arguments = @("-m", "media_security.cli", $Target, "--json-out", $JsonOut)
if ($Recursive) {
    $arguments += "--recursive"
}

python $arguments
