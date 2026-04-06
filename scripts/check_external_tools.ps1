param(
    [switch]$Strict,
    [switch]$InstallMissing,
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"

$toolHints = @{
    "ffprobe" = @(
        "winget install Gyan.FFmpeg",
        "choco install ffmpeg -y",
        "Manual install: https://ffmpeg.org/download.html"
    )
    "exiftool" = @(
        "winget install OliverBetz.ExifTool",
        "choco install exiftool -y",
        "Manual install: https://exiftool.org/"
    )
}

function Test-Tool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Resolve-ToolPath {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("ffprobe", "exiftool")]
        [string]$Name
    )

    $toolEnvVars = @{
        "ffprobe" = "MEDIA_SECURITY_FFPROBE_PATH"
        "exiftool" = "MEDIA_SECURITY_EXIFTOOL_PATH"
    }
    $toolRelativePaths = @{
        "ffprobe" = @(
            "ffmpeg\\bin\\ffprobe.exe",
            "ffprobe\\ffprobe.exe",
            "ffprobe.exe"
        )
        "exiftool" = @(
            "exiftool\\exiftool.exe",
            "exiftool\\exiftool(-k).exe",
            "exiftool.exe"
        )
    }

    $explicitPath = [System.Environment]::GetEnvironmentVariable($toolEnvVars[$Name], "Process")
    if ([string]::IsNullOrWhiteSpace($explicitPath)) {
        $explicitPath = [System.Environment]::GetEnvironmentVariable($toolEnvVars[$Name], "User")
    }
    if ([string]::IsNullOrWhiteSpace($explicitPath)) {
        $explicitPath = [System.Environment]::GetEnvironmentVariable($toolEnvVars[$Name], "Machine")
    }
    if (-not [string]::IsNullOrWhiteSpace($explicitPath) -and (Test-Path -LiteralPath $explicitPath -PathType Leaf)) {
        return @{
            Found = $true
            Path = (Resolve-Path -LiteralPath $explicitPath).Path
            Source = "env"
        }
    }

    $candidateRoots = New-Object System.Collections.Generic.List[string]
    $sharedToolsDir = [System.Environment]::GetEnvironmentVariable("MEDIA_SECURITY_TOOLS_DIR", "Process")
    if ([string]::IsNullOrWhiteSpace($sharedToolsDir)) {
        $sharedToolsDir = [System.Environment]::GetEnvironmentVariable("MEDIA_SECURITY_TOOLS_DIR", "User")
    }
    if ([string]::IsNullOrWhiteSpace($sharedToolsDir)) {
        $sharedToolsDir = [System.Environment]::GetEnvironmentVariable("MEDIA_SECURITY_TOOLS_DIR", "Machine")
    }
    if (-not [string]::IsNullOrWhiteSpace($sharedToolsDir)) {
        $candidateRoots.Add($sharedToolsDir)
    }
    $candidateRoots.Add((Join-Path $ProjectRoot "media_security\\vendor\\tools"))
    $candidateRoots.Add((Join-Path $ProjectRoot "vendor\\tools"))

    foreach ($root in $candidateRoots | Select-Object -Unique) {
        if ([string]::IsNullOrWhiteSpace($root)) {
            continue
        }

        foreach ($relativePath in $toolRelativePaths[$Name]) {
            foreach ($candidate in @(
                (Join-Path $root ("windows\\" + $relativePath)),
                (Join-Path $root $relativePath)
            )) {
                if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                    return @{
                        Found = $true
                        Path = (Resolve-Path -LiteralPath $candidate).Path
                        Source = "bundled"
                    }
                }
            }
        }
    }

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return @{
            Found = $true
            Path = $command.Source
            Source = "path"
        }
    }

    return @{
        Found = $false
        Path = $null
        Source = $null
    }
}

function Refresh-Path {
    $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $paths = @($machinePath, $userPath) | Where-Object { $_ -and $_.Trim() -ne "" }
    if ($paths.Count -gt 0) {
        $env:Path = ($paths -join ";")
    }
}

function Install-Tool {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("ffprobe", "exiftool")]
        [string]$Tool
    )

    $installAttempts = @()

    if (Test-Tool -Name "winget") {
        if ($Tool -eq "ffprobe") {
            $installAttempts += @(
                @{
                    Name = "winget"
                    Command = @(
                        "winget",
                        "install",
                        "--id",
                        "Gyan.FFmpeg",
                        "-e",
                        "--accept-package-agreements",
                        "--accept-source-agreements"
                    )
                }
            )
        }
        else {
            $installAttempts += @(
                @{
                    Name = "winget"
                    Command = @(
                        "winget",
                        "install",
                        "--id",
                        "OliverBetz.ExifTool",
                        "-e",
                        "--accept-package-agreements",
                        "--accept-source-agreements"
                    )
                }
            )
        }
    }

    if (Test-Tool -Name "choco") {
        if ($Tool -eq "ffprobe") {
            $installAttempts += @(
                @{
                    Name = "choco"
                    Command = @("choco", "install", "ffmpeg", "-y")
                }
            )
        }
        else {
            $installAttempts += @(
                @{
                    Name = "choco"
                    Command = @("choco", "install", "exiftool", "-y")
                }
            )
        }
    }

    if ($installAttempts.Count -eq 0) {
        Write-Host "No supported package manager found (winget/choco)." -ForegroundColor Yellow
        return $false
    }

    foreach ($attempt in $installAttempts) {
        $command = $attempt.Command
        $runner = $command[0]
        $args = @()
        if ($command.Length -gt 1) {
            $args = $command[1..($command.Length - 1)]
        }

        Write-Host "Trying install via $($attempt.Name): $($command -join ' ')" -ForegroundColor Cyan
        try {
            & $runner @args
            if ($LASTEXITCODE -ne 0) {
                Write-Host "Installer exited with code $LASTEXITCODE." -ForegroundColor DarkYellow
                continue
            }

            Refresh-Path
            if (Test-Tool -Name $Tool) {
                return $true
            }
        }
        catch {
            Write-Host "Install attempt failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
        }
    }

    return $false
}

$missing = New-Object System.Collections.Generic.List[string]

foreach ($tool in @("ffprobe", "exiftool")) {
    $toolInfo = Resolve-ToolPath -Name $tool
    if (-not $toolInfo.Found) {
        Write-Host "[MISSING] $tool" -ForegroundColor Yellow
        if ($InstallMissing) {
            Write-Host "Auto-install is enabled, trying to install $tool..." -ForegroundColor Cyan
            $installed = Install-Tool -Tool $tool
            if ($installed) {
                Write-Host "[INSTALLED] $tool" -ForegroundColor Green
            }
            else {
                $missing.Add($tool)
            }
        }
        else {
            $missing.Add($tool)
        }
        continue
    }

    Write-Host "[OK] $tool -> $($toolInfo.Path) [$($toolInfo.Source)]" -ForegroundColor Green
    try {
        if ($tool -eq "ffprobe") {
            $versionLine = (& $toolInfo.Path -version 2>$null | Select-Object -First 1)
        } else {
            $versionLine = "exiftool " + (& $toolInfo.Path -ver 2>$null | Select-Object -First 1)
        }
        if ($versionLine) {
            Write-Host "      $versionLine"
        }
    } catch {
        Write-Host "      Version check failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}

if ($missing.Count -gt 0) {
    Write-Host ""
    Write-Host "Install missing tools and reopen the terminal so PATH is refreshed." -ForegroundColor Yellow
    foreach ($tool in $missing) {
        Write-Host ""
        Write-Host "Suggested install commands for ${tool}:" -ForegroundColor Cyan
        foreach ($hint in $toolHints[$tool]) {
            Write-Host "  - $hint"
        }
    }
    if ($Strict) {
        exit 1
    }
}

Write-Host ""
Write-Host "Tool check complete." -ForegroundColor Green
