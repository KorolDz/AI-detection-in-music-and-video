param(
    [switch]$Strict
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$safeProjectRoot = (Resolve-Path -Path $projectRoot).Path.Replace("\", "/")

if ($null -eq (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "Git is not available in PATH." -ForegroundColor Red
    if ($Strict) {
        exit 1
    }
    return
}

$patterns = @(
    @{ Name = "Private key block"; Regex = "-----BEGIN (RSA|EC|OPENSSH|DSA|PRIVATE) KEY-----" }
    @{ Name = "AWS access key"; Regex = "AKIA[0-9A-Z]{16}" }
    @{ Name = "GitHub token"; Regex = "gh[pousr]_[A-Za-z0-9_]{20,}" }
    @{ Name = "OpenAI key"; Regex = "sk-[A-Za-z0-9]{20,}" }
    @{ Name = "Slack token"; Regex = "xox[baprs]-[A-Za-z0-9-]{12,}" }
    @{ Name = "JWT token"; Regex = "eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}" }
    @{
        Name = "Credential assignment"
        Regex = "(?i)\b(api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*[""'][^""']{8,}[""']"
    }
    @{
        Name = "Connection string credentials"
        Regex = "(?i)\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^/\s:@]+:[^@\s]+@"
    }
)

$allowlistRegex = @(
    "postgresql://postgres:postgres@localhost:5432/media_security",
    "postgresql://user:pass@host:5432/dbname",
    "POSTGRES_PASSWORD:\s*postgres",
    "user,\s*_password\s*=\s*user_info\.split\(",
    "example",
    "\.example"
)

$binaryExtensions = @(
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico",
    ".mp3", ".wav", ".mp4", ".avi", ".mov",
    ".zip", ".7z", ".rar", ".tar", ".gz", ".bz2",
    ".pdf", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx"
)

$skipPrefixes = @(
    "datasets/",
    "reports/",
    ".git/"
)

function Test-Allowlisted {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LineText
    )

    foreach ($rule in $allowlistRegex) {
        if ($LineText -match $rule) {
            return $true
        }
    }
    return $false
}

function Should-SkipPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    $normalized = $RelativePath.Replace("\", "/")
    foreach ($prefix in $skipPrefixes) {
        if ($normalized.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    $extension = [System.IO.Path]::GetExtension($normalized).ToLowerInvariant()
    return $binaryExtensions -contains $extension
}

$trackedFiles = & git -c "safe.directory=$safeProjectRoot" -C $projectRoot ls-files
if ($LASTEXITCODE -ne 0) {
    throw "Unable to list tracked files with git."
}

$findings = New-Object System.Collections.Generic.List[object]

foreach ($relativePath in $trackedFiles) {
    if ([string]::IsNullOrWhiteSpace($relativePath)) {
        continue
    }
    if (Should-SkipPath -RelativePath $relativePath) {
        continue
    }

    $absolutePath = Join-Path $projectRoot $relativePath
    if (-not (Test-Path -Path $absolutePath -PathType Leaf)) {
        continue
    }

    foreach ($pattern in $patterns) {
        try {
            $matches = Select-String -Path $absolutePath -Pattern $pattern.Regex -AllMatches -Encoding UTF8
        } catch {
            continue
        }

        foreach ($match in $matches) {
            $lineText = ""
            if ($match.Line) {
                $lineText = $match.Line.Trim()
            }
            if (-not $lineText) {
                continue
            }
            if (Test-Allowlisted -LineText $lineText) {
                continue
            }

            $findings.Add(
                [PSCustomObject]@{
                    File    = $relativePath
                    Line    = $match.LineNumber
                    Pattern = $pattern.Name
                    Snippet = $lineText
                }
            ) | Out-Null
        }
    }
}

if ($findings.Count -gt 0) {
    Write-Host "[FAIL] Potential secrets detected in tracked files:" -ForegroundColor Red
    foreach ($item in $findings) {
        Write-Host (" - {0}:{1} [{2}] {3}" -f $item.File, $item.Line, $item.Pattern, $item.Snippet) -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "Commit/push blocked. Move secrets to environment variables or secret manager." -ForegroundColor Red
    exit 1
}

Write-Host "[OK] Secret scan passed for tracked files." -ForegroundColor Green
exit 0
