#!/usr/bin/env pwsh
# Heimdall Quick Launcher
# Usage: .\run.ps1 [serve|test|ollama|cli]

param([string]$Command = "serve")

$ProjectRoot = $PSScriptRoot
$Venv = "$ProjectRoot\.venv\Scripts"
$Ollama = "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe"

& "$Venv\Activate.ps1"

switch ($Command) {
    "serve" {
        Write-Host "`n[Heimdall] Starting at http://localhost:8000/ui`n" -ForegroundColor Cyan
        & "$Venv\uvicorn.exe" heimdall.api.app:app --reload --port 8000
    }
    "test" {
        Write-Host "`n[Heimdall] Running tests...`n" -ForegroundColor Yellow
        & "$Venv\pytest.exe" tests/ -v
    }
    "ollama" {
        Write-Host "[Ollama] Starting server..." -ForegroundColor Green
        Start-Process $Ollama -ArgumentList "serve" -WindowStyle Normal
        Start-Sleep 3
        Write-Host "[Ollama] Pulling qwen2.5:0.5b (~400MB)..." -ForegroundColor Green
        & $Ollama pull qwen2.5:0.5b
        Write-Host "[Ollama] Done! Restart Heimdall to activate AI Copilot." -ForegroundColor Green
    }
    "cli" {
        & "$Venv\python.exe" -m heimdall.cli @args
    }
    default {
        Write-Host "Usage: .\run.ps1 [serve|test|ollama|cli]"
    }
}
