param(
    [string]$Snapshot = "database_snapshot"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    throw "Virtual environment not found. Run scripts\setup-delivery.ps1 first."
}

.\.venv\Scripts\python.exe scripts\restore_delivery_snapshot.py --snapshot $Snapshot
