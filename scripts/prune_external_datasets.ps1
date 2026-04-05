param(
    [string]$Root = "datasets",
    [int]$Keep = 15,
    [switch]$WhatIf
)

if ($Keep -lt 1) {
    throw "Keep must be >= 1."
}

$projectRoot = (Resolve-Path ".").Path
$datasetRoot = (Resolve-Path $Root).Path

if (-not $datasetRoot.StartsWith($projectRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Target root must be inside project root."
}

Get-ChildItem -LiteralPath $datasetRoot -Directory | Sort-Object FullName | ForEach-Object {
    $folder = $_
    $files = Get-ChildItem -LiteralPath $folder.FullName -File -Recurse -ErrorAction SilentlyContinue |
        Sort-Object FullName

    if ($files.Count -le $Keep) {
        Write-Host "[KEEP] $($folder.Name): $($files.Count) files"
        return
    }

    $toDelete = $files | Select-Object -Skip $Keep

    foreach ($file in $toDelete) {
        $resolved = (Resolve-Path -LiteralPath $file.FullName).Path
        if (-not $resolved.StartsWith($datasetRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Path outside allowed root: $resolved"
        }
    }

    if ($WhatIf) {
        Write-Host "[DRY-RUN] $($folder.Name): delete=$($toDelete.Count), keep=$Keep"
        return
    }

    foreach ($file in $toDelete) {
        Remove-Item -LiteralPath $file.FullName -Force
    }
    Write-Host "[DONE] $($folder.Name): deleted=$($toDelete.Count), kept=$Keep"
}
