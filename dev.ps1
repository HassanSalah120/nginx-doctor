$ErrorActionPreference = 'Stop'

function Stop-Tree {
    param([int]$Pid)

    try {
        if ($Pid -le 0) { return }
        $proc = Get-Process -Id $Pid -ErrorAction SilentlyContinue
        if (-not $proc) { return }

        # Try graceful first
        try { Stop-Process -Id $Pid -ErrorAction SilentlyContinue } catch {}

        Start-Sleep -Milliseconds 300

        # Ensure children are gone (best-effort)
        try {
            $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$Pid" -ErrorAction SilentlyContinue
            foreach ($c in ($children | ForEach-Object { $_.ProcessId })) {
                try { Stop-Process -Id $c -Force -ErrorAction SilentlyContinue } catch {}
            }
        } catch {}
    } catch {}
}

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$webUi = Join-Path $root 'web-ui'

Write-Host "Starting FastAPI on http://127.0.0.1:8765 ..."
$api = Start-Process -FilePath python -ArgumentList @('-m','nginx_doctor','web','--port','8765') -WorkingDirectory $root -PassThru

Write-Host "Starting React dev server (Vite) ..."
$ui = Start-Process -FilePath npm -ArgumentList @('run','dev') -WorkingDirectory $webUi -PassThru

Write-Host ""
Write-Host "Dev stack is running:" 
Write-Host "- FastAPI: http://127.0.0.1:8765" 
Write-Host "- Vite UI: shown in the Vite output window" 
Write-Host ""
Write-Host "Press Ctrl+C to stop both." 

try {
    while ($true) {
        Start-Sleep -Seconds 1

        if ($api.HasExited) {
            Write-Host "FastAPI process exited." -ForegroundColor Red
            break
        }

        if ($ui.HasExited) {
            Write-Host "Vite dev server exited." -ForegroundColor Red
            break
        }
    }
}
finally {
    Write-Host "Stopping dev stack..." -ForegroundColor Yellow
    Stop-Tree -Pid $ui.Id
    Stop-Tree -Pid $api.Id
}
