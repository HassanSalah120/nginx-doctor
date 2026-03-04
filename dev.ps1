$ErrorActionPreference = 'Stop'

function Stop-Tree {
    param([int]$ProcessId)

    try {
        if ($ProcessId -le 0) { return }
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if (-not $proc) { return }

        # Try graceful first
        try { Stop-Process -Id $ProcessId -ErrorAction SilentlyContinue } catch {}

        Start-Sleep -Milliseconds 300

        # Ensure children are gone (best-effort)
        try {
            $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$ProcessId" -ErrorAction SilentlyContinue
            foreach ($c in ($children | ForEach-Object { $_.ProcessId })) {
                try { Stop-Process -Id $c -Force -ErrorAction SilentlyContinue } catch {}
            }
        } catch {}
    } catch {}
}

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$webUi = Join-Path $root 'web-ui'

if (-not (Test-Path $webUi)) {
    throw "web-ui folder not found at: $webUi"
}

$pythonExe = (Get-Command python -ErrorAction Stop).Source

# On Windows, npm is typically a cmd shim (npm.cmd). Start-Process works more reliably with full path.
$npmExe = $null
try {
    $npmExe = (Get-Command npm.cmd -ErrorAction Stop).Source
} catch {
    $npmExe = (Get-Command npm -ErrorAction Stop).Source
}

$apiOut = Join-Path $root '.dev-api.out.log'
$apiErr = Join-Path $root '.dev-api.err.log'
$uiOut = Join-Path $root '.dev-ui.out.log'
$uiErr = Join-Path $root '.dev-ui.err.log'

"" | Out-File -FilePath $apiOut -Encoding utf8
"" | Out-File -FilePath $apiErr -Encoding utf8
"" | Out-File -FilePath $uiOut -Encoding utf8
"" | Out-File -FilePath $uiErr -Encoding utf8

Write-Host "Starting FastAPI on http://127.0.0.1:8765 ..."
$api = Start-Process -FilePath $pythonExe -ArgumentList @('-m','nginx_doctor','web','--port','8765') -WorkingDirectory $root -PassThru -RedirectStandardOutput $apiOut -RedirectStandardError $apiErr

Write-Host "Starting React dev server (Vite) ..."
$ui = Start-Process -FilePath $npmExe -ArgumentList @('run','dev') -WorkingDirectory $webUi -PassThru -RedirectStandardOutput $uiOut -RedirectStandardError $uiErr

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
            if (Test-Path $apiErr) {
                Write-Host "--- FastAPI stderr (tail) ---" -ForegroundColor Yellow
                Get-Content -Path $apiErr -Tail 60 | ForEach-Object { Write-Host $_ }
            }
            if (Test-Path $apiOut) {
                Write-Host "--- FastAPI stdout (tail) ---" -ForegroundColor Yellow
                Get-Content -Path $apiOut -Tail 60 | ForEach-Object { Write-Host $_ }
            }
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
    Stop-Tree -ProcessId $ui.Id
    Stop-Tree -ProcessId $api.Id
}
