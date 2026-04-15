$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
Set-Location $projectRoot

$pythonCandidates = @(
    @{ Command = "py"; Args = @("-3.11") },
    @{ Command = "python"; Args = @() }
)

$selectedPython = $null
foreach ($candidate in $pythonCandidates) {
    try {
        & $candidate.Command @($candidate.Args + @("--version")) | Out-Null
        $selectedPython = $candidate
        break
    }
    catch {
    }
}

if ($null -eq $selectedPython) {
    throw "Python was not found. Install Python 3.11 and try again."
}

$venvPath = Join-Path $projectRoot ".venv"
$venvPython = Join-Path $venvPath "Scripts\\python.exe"

if (-not (Test-Path $venvPython)) {
    Write-Host "Creating virtual environment..."
    & $selectedPython.Command @($selectedPython.Args + @("-m", "venv", $venvPath))
}

Write-Host "Upgrading pip tools..."
& $venvPython -m pip install --upgrade pip "setuptools<82" wheel

Write-Host "Installing dependencies from requirements.txt..."
& $venvPython -m pip install -r requirements.txt

Write-Host ""
Write-Host "Done."
Write-Host "Run the app:"
Write-Host ".\\.venv\\Scripts\\python -m desktop_app"
Write-Host ""
Write-Host "Run tests:"
Write-Host ".\\.venv\\Scripts\\python -m unittest discover -s tests -v"
