$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

foreach ($port in @(8000, 8501)) {
    $listener = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue
    if ($listener) {
        throw "Port $port is already in use. Stop that service before starting the project."
    }
}

$env:TARA_API_URL = "http://127.0.0.1:8000"
$api = Start-Process -FilePath "python" `
    -ArgumentList @("-m", "uvicorn", "app.api:app", "--host", "127.0.0.1", "--port", "8000") `
    -WorkingDirectory $root -PassThru

$deadline = (Get-Date).AddMinutes(3)
do {
    Start-Sleep -Seconds 2
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -TimeoutSec 5
        break
    } catch {
        if ($api.HasExited) {
            throw "The API process exited before becoming healthy (exit code $($api.ExitCode))."
        }
    }
} while ((Get-Date) -lt $deadline)

if (-not $health) {
    throw "The API did not become healthy within three minutes."
}

$ui = Start-Process -FilePath "python" `
    -ArgumentList @("-m", "streamlit", "run", "ui/streamlit_app.py", "--server.address", "127.0.0.1", "--server.port", "8501") `
    -WorkingDirectory $root -PassThru

Write-Output "API (PID $($api.Id)): http://127.0.0.1:8000/docs"
Write-Output "UI (PID $($ui.Id)): http://127.0.0.1:8501"
