#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

$ErrorActionPreference = "Stop"

function Have($cmd) { return (Get-Command $cmd -ErrorAction SilentlyContinue) -ne $null }

function Invoke-PythonBlock([string]$Code){
  $tmp = [System.IO.Path]::ChangeExtension([System.IO.Path]::GetTempFileName(), ".py")
  Set-Content -LiteralPath $tmp -Value $Code -Encoding UTF8
  try {
    & $PY $tmp
  } finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
  }
}

Write-Host "[INFO] Sistema: Windows"

if (-not (Have "python") -and -not (Have "py")) {
    Write-Warning "Instala Python desde https://www.python.org/downloads/windows/ (incluye Tk)."
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
Write-Host "Verificando tkinter…"
  Invoke-PythonBlock @"
import sys
try:
    import tkinter as tk
    r = tk.Tk(); r.withdraw(); r.destroy()
except Exception as e:
    raise SystemExit(f"tkinter no disponible: {e}")
"@

Write-Host ""
Write-Host "Listo para usar."
Write-Host "Siguientes pasos:"
Write-Host "  1) Define la API key de OpenAI:"
Write-Host '     $Env:OPENAI_API_KEY = "sk-xxxx"'
Write-Host "  2) Ejecuta la app:"
Write-Host "     python .\main.py"