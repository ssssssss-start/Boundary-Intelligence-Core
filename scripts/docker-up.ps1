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

Write-Host "Building and starting the complete anti-fraud stack..."
Invoke-CheckedDocker @("info")
Invoke-CheckedDocker @("compose", "-f", $composeFile, "up", "-d", "--build", "--remove-orphans")

Write-Host ""
Write-Host "Current containers:"
Invoke-CheckedDocker @("compose", "-f", $composeFile, "ps")

Write-Host ""
Write-Host "Service endpoints:"
Write-Host "Import:  http://localhost:8000/import.html"
Write-Host "Chat:    http://localhost:8001/chat.html"
Write-Host "Milvus:  http://localhost:19530"
Write-Host "MongoDB: mongodb://localhost:27017"
