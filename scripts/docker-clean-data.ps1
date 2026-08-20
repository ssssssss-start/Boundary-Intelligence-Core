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

Write-Host "This will stop containers and delete Milvus/MongoDB Docker volumes for this project."
Write-Host "Use this only when you want to reset all imported anti-fraud knowledge and chat history."
$answer = Read-Host "Type RESET to continue"

if ($answer -ne "RESET") {
    Write-Host "Cancelled."
    exit 0
}

Invoke-CheckedDocker @("compose", "-f", $composeFile, "down", "-v")
Write-Host "Containers stopped and project volumes deleted."
