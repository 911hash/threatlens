# ThreatLens - Start backend and frontend (Windows PowerShell)
$ErrorActionPreference = "Stop"
Write-Host "=== Starting ThreatLens Dev Environment ===" -ForegroundColor Cyan

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# 1. Environment file check
if (-not (Test-Path ".env")) {
    if (Test-Path ".env.example") {
        Write-Host "Creating .env from .env.example..." -ForegroundColor Yellow
        Copy-Item ".env.example" ".env"
    }
}

# 2. Backend virtual environment
Set-Location "$ScriptDir\backend"
if (-not (Test-Path "venv")) {
    Write-Host "Creating Python virtual environment in backend/venv..." -ForegroundColor Yellow
    python -m venv venv
}

Write-Host "Checking backend dependencies..." -ForegroundColor Cyan
& ".\venv\Scripts\pip.exe" install -r requirements.txt

# 3. Frontend setup
Set-Location "$ScriptDir\frontend"
if (-not (Test-Path "node_modules")) {
    Write-Host "Installing frontend dependencies..." -ForegroundColor Yellow
    npm.cmd install
}

# 4. Start servers
Write-Host "Starting Backend on http://localhost:8000..." -ForegroundColor Green
$backendProc = Start-Process -FilePath "$ScriptDir\backend\venv\Scripts\uvicorn.exe" -ArgumentList "app.main:app --host 127.0.0.1 --port 8000 --reload" -WorkingDirectory "$ScriptDir\backend" -PassThru

Write-Host "Starting Frontend on http://localhost:5173..." -ForegroundColor Green
$frontendProc = Start-Process -FilePath "npm.cmd" -ArgumentList "run dev -- --host" -WorkingDirectory "$ScriptDir\frontend" -PassThru

Write-Host "ThreatLens is running!" -ForegroundColor Green
Write-Host "Backend API:  http://localhost:8000" -ForegroundColor Cyan
Write-Host "Frontend App: http://localhost:5173" -ForegroundColor Cyan
Write-Host "Press Ctrl+C or close this window to exit." -ForegroundColor Gray

try {
    Wait-Process -Id $backendProc.Id, $frontendProc.Id
} finally {
    if (-not $backendProc.HasExited) { Stop-Process -Id $backendProc.Id -Force }
    if (-not $frontendProc.HasExited) { Stop-Process -Id $frontendProc.Id -Force }
}
