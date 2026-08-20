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

Write-Host "Anti-fraud RAG infrastructure status:"
Invoke-CheckedDocker @("compose", "-f", $composeFile, "ps")

Write-Host ""
Write-Host "Raw Docker containers:"
Invoke-CheckedDocker @("ps", "--filter", "name=anti-fraud-", "--format", "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}")
