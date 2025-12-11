#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

$ErrorActionPreference = "Stop"

function Have($cmd) { return (Get-Command $cmd -ErrorAction SilentlyContinue) -ne $null }

Write-Host "[INFO] Sistema: Windows"

if (-not (Have "python") -and -not (Have "py")) {
  if (Have "winget") {
    Write-Host "[INFO] Instalando Python con winget…"
    winget install -e --id Python.Python.3.12 --source winget --silent
  } else {
    Write-Warning "Instala Python desde https://www.python.org/downloads/windows/ (incluye Tk)."
  }
}

$PY = $(if (Have "py") { "py" } elseif (Have "python") { "python" } else { "" })
if ($PY -eq "") { throw "Python no encontrado en PATH." }

Write-Host "[INFO] Creando venv .venv…"
& $PY -3 -m venv .venv

Write-Host "[INFO] Activando venv…"
$venv = ".\.venv\Scripts\Activate.ps1"
if (-not (Test-Path $venv)) { throw "No se encontró $venv" }
. $venv

Write-Host "[INFO] Actualizando pip/setuptools/wheel…"
python -m pip install -U pip setuptools wheel

if (Test-Path ".\requirements.txt") {
  Write-Host "[INFO] Instalando requirements.txt…"
  pip install -r requirements.txt
} else {
  Write-Host "[INFO] Instalando dependencias mínimas…"
  pip install "openai==1.*"
}

Write-Host "[INFO] Verificando tkinter…"
python - << 'PY'
try:
    import tkinter as tk
    import sys
    r = tk.Tk()
    r.withdraw()
    print(f"OK tkinter v{tk.TkVersion} (Python {sys.version.split()[0]})")
    r.destroy()
except Exception as e:
    print("FALLO tkinter:", e)
    raise SystemExit(1)
PY

Write-Host ""
Write-Host "Listo ✅"
Write-Host "Siguientes pasos:"
Write-Host "  1) Define la API key de OpenAI:"
Write-Host '     $Env:OPENAI_API_KEY = "sk-xxxx"'
Write-Host "  2) Ejecuta la app:"
Write-Host "     python .\main.py"