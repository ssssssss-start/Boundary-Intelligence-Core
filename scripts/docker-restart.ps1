$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$composeFile = Join-Path $projectRoot "docker-compose.yml"

function Invoke-CheckedDocker {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Docker command failed: docker $($Arguments -join ' ')"
    }
}

if (-not (Test-Path $composeFile)) {
    throw "docker-compose.yml not found: $composeFile"
}

Write-Host "Restarting anti-fraud RAG infrastructure..."
Invoke-CheckedDocker @("compose", "-f", $composeFile, "restart")

Write-Host ""
Invoke-CheckedDocker @("compose", "-f", $composeFile, "ps")
