<#  run.ps1
    PowerShell 7+ cross-platform runner for the Docker security scanner prototype
#>

[CmdletBinding()]
param(
  [switch]$SkipTkCheck,
  [switch]$SkipDockerCheck,
  [switch]$WithTrivyCheck,
  [switch]$Ui,                         # force GUI
  [string]$Image,                      # path to .tar|.tar.gz
  [switch]$AutoLoad,                   # docker load -i <image>
  [string]$Name,                       # repo:tag
  [switch]$Scan,                       # trivy image -> JSON
  [switch]$Llm,                        # analyze JSON with llm_analyzer
  [switch]$LlmStream,                  # streaming analysis
  [string]$Output = "output/result.json",
  [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------- helpers ----------
function Write-Info($msg){ Write-Host "[INFO]" -ForegroundColor Cyan -NoNewline; Write-Host " $msg" }
function Write-Warn($msg){ Write-Host "[WARN]" -ForegroundColor Yellow -NoNewline; Write-Host " $msg" }
function Write-Err ($msg){ Write-Host "[ERR ]" -ForegroundColor Red -NoNewline; Write-Host " $msg" }
function Have($cmd){ try { $null = Get-Command $cmd -ErrorAction Stop; $true } catch { $false } }

function Show-Usage {
@"
Usage:
  pwsh ./run.ps1 [options]

General:
  -SkipTkCheck            No verificar tkinter
  -SkipDockerCheck        No verificar Docker
  -WithTrivyCheck         Verificar Trivy instalado
  -Ui                     Forzar iniciar GUI (Tk)

Headless (CLI):
  -Image <path.tar[.gz]>  Ruta de la imagen Docker exportada
  -AutoLoad               Ejecutar 'docker load -i <image>' y detectar repo:tag
  -Name <repo:tag>        Nombre de imagen (si no usas -AutoLoad)
  -Scan                   Ejecutar 'trivy image' y guardar JSON
  -Llm                    Analizar JSON con llm_analyzer (resumen + LLM)
  -LlmStream              Análisis en streaming
  -Output <file>          Archivo JSON (default: output/result.json)

Ejemplos:
  pwsh ./run.ps1                  # GUI por defecto
  pwsh ./run.ps1 -Image .\ubuntu.tar.gz -AutoLoad -Scan -Llm
  pwsh ./run.ps1 -Name ubuntu:latest -Scan -Output output\ubuntu.json
"@ | Write-Host
}

if ($Help) { Show-Usage; exit 0 }

# Move to script directory
if ($MyInvocation.MyCommand.Path) {
  Set-Location -LiteralPath (Split-Path -Parent $MyInvocation.MyCommand.Path)
}

# ---------- .env loader ----------
function Load-DotEnv {
  [CmdletBinding()]
  param(
    [string]$Path = ".env",
    [switch]$Force,     # sobrescribe si ya existe
    [switch]$Expand     # expande ${VAR} con variables ya en Env:
  )

  if (-not (Test-Path -LiteralPath $Path)) {
    throw "No existe el archivo: $Path"
  }

  foreach ($raw in Get-Content -LiteralPath $Path) {
    $line = $raw.Trim()
    if (-not $line -or $line.StartsWith('#')) { continue }
    if ($line.StartsWith('export ')) { $line = $line.Substring(7).Trim() }

    $eq = $line.IndexOf('=')
    if ($eq -lt 1) { continue }

    $key = $line.Substring(0, $eq).Trim()
    if (-not $key) { continue }

    $val = $line.Substring($eq + 1).Trim()

    # Quitar comillas y soportar escapes básicos en comillas dobles
    if ($val.StartsWith("'") -and $val.EndsWith("'")) {
      $val = $val.Substring(1, $val.Length - 2)
    } elseif ($val.StartsWith('"') -and $val.EndsWith('"')) {
      $val = $val.Substring(1, $val.Length - 2).Replace('\"','"')
      $val = $val.Replace('\n',"`n").Replace('\r',"`r").Replace('\t',"`t")
    } else {
      # Comentario inline: KEY=VAL # comentario
      $hashIx = $val.IndexOf(' #')
      if ($hashIx -gt -1) { $val = $val.Substring(0, $hashIx).TrimEnd() }
    }

    if ($Expand) {
      $val = [regex]::Replace($val, '\$\{([A-Za-z_][A-Za-z0-9_]*)\}', {
        param($m)
        (Get-Item -Path ("Env:" + $m.Groups[1].Value) -ErrorAction SilentlyContinue).Value ?? ''
      })
    }

    $exists = Test-Path ("Env:$key")
    if ($Force -or -not $exists) {
      Set-Item -Path ("Env:$key") -Value $val
    }
  }
}
Load-DotEnv

# bridge OPENAPI_API_KEY -> OPENAI_API_KEY if needed
if ([string]::IsNullOrWhiteSpace($env:OPENAI_API_KEY) -and -not [string]::IsNullOrWhiteSpace($env:OPENAPI_API_KEY)) {
  $env:OPENAI_API_KEY = $env:OPENAPI_API_KEY
}

# ---------- Python / venv ----------
$IsWin = $null -ne $PSStyle -and $env:OS -match 'Windows' -or $IsWindows
$venvPython = if ($IsWin) { ".\.venv\Scripts\python.exe" } else { "./.venv/bin/python" }

function Resolve-Python {
  if (Test-Path $venvPython) { return (Resolve-Path $venvPython).Path }
  if (Have "python3") { return "python3" }
  if (Have "python") { return "python" }
  throw "Python no está instalado."
}

$PY = Resolve-Python

if (-not (Test-Path $venvPython)) {
  Write-Warn "No hay .venv. Creando virtualenv e instalando dependencias…"
  & $PY -m venv .venv
  if (-not (Test-Path $venvPython)) { throw "Falló la creación del venv." }
  $PY = (Resolve-Path $venvPython).Path
  & $PY -m pip install -U pip setuptools wheel
  if (Test-Path "requirements.txt") {
    & $PY -m pip install -r requirements.txt
  } else {
    & $PY -m pip install "openai==1.*"
  }
} else {
  $PY = (Resolve-Path $venvPython).Path
}

# helper para ejecutar bloques python desde PS (escribe temp .py)
function Invoke-PythonBlock([string]$Code){
  $tmp = [System.IO.Path]::ChangeExtension([System.IO.Path]::GetTempFileName(), ".py")
  Set-Content -LiteralPath $tmp -Value $Code -Encoding UTF8
  try {
    & $PY $tmp
  } finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
  }
}

# ---------- Checks ----------
if (-not $SkipTkCheck) {
  Write-Info "Verificando tkinter…"
  Invoke-PythonBlock @"
import sys
try:
    import tkinter as tk
    r = tk.Tk(); r.withdraw(); print("tkinter OK"); r.destroy()
except Exception as e:
    raise SystemExit(f"tkinter no disponible: {e}")
"@
}

if (-not $SkipDockerCheck) {
  if (-not (Have "docker")) { Write-Err "Docker no está en PATH."; exit 1 }
  try {
    docker info | Out-Null
  } catch {
    Write-Err "Docker daemon no está corriendo."
    exit 1
  }
  Write-Info "Docker OK"
}

if ($WithTrivyCheck -or $Scan) {
  if (-not (Have "trivy")) { Write-Err "Trivy no encontrado. Instálalo o quita -Scan / -WithTrivyCheck."; exit 1 }
  Write-Info "Trivy OK"
}

# ---------- AutoLoad ----------
if ($AutoLoad) {
  if ([string]::IsNullOrWhiteSpace($Image)) { Write-Err "-AutoLoad requiere -Image <path.tar.gz>"; exit 1 }
  if (-not (Test-Path $Image)) { Write-Err "No existe el archivo: $Image"; exit 1 }
  Write-Info "Cargando imagen: $Image"
  $loadOut = (docker load -i $Image) 2>&1
  $match = ($loadOut -split "`r?`n") | Where-Object { $_ -match 'Loaded image:\s*(.+)$' } | Select-Object -Last 1
  if ($match) {
    $Name = ($match -replace '^.*Loaded image:\s*','').Trim()
    Write-Info "Imagen detectada: $Name"
  } else {
    Write-Warn "No se detectó 'Loaded image: ...' en la salida. Debes pasar -Name <repo:tag>."
  }
}

# ---------- Scan ----------
if ($Scan) {
  if ([string]::IsNullOrWhiteSpace($Name)) { Write-Err "-Scan requiere -Name <repo:tag> (o usa -AutoLoad)."; exit 1 }
  $outDir = Split-Path -Parent $Output
  if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
  Write-Info "Escaneando imagen con Trivy: $Name"
  trivy image $Name --format json --output $Output
  Write-Info "Resultado guardado en: $Output"
}

# ---------- LLM ----------
if ($Llm) {
  if (-not (Test-Path $Output)) { Write-Err "-Llm requiere JSON en: $Output (ejecuta -Scan antes)"; exit 1 }
  if ([string]::IsNullOrWhiteSpace($env:OPENAI_API_KEY) -and [string]::IsNullOrWhiteSpace($env:OPENAPI_API_KEY)) {
    Write-Warn "OPENAI_API_KEY no está definida; la llamada al LLM fallará."
  }
  Write-Info "Ejecutando análisis LLM…"
  Invoke-PythonBlock @"
from llm_analyzer import resumir_cves, consultar_llm
summary, metrics = resumir_cves(r'''$Output''')
print('\n=== Resumen CVEs (primeras líneas) ===')
print(summary.splitlines()[:10])
print('\n=== Recomendaciones LLM ===')
print(consultar_llm(summary, metrics))
"@
}

if ($LlmStream) {
  if (-not (Test-Path $Output)) { Write-Err "-LlmStream requiere JSON en: $Output (usa -Scan antes)"; exit 1 }
  Write-Info "LLM streaming (CLI)…"
  Invoke-PythonBlock @"
from llm_analyzer import resumir_cves, stream_to_stdout
summary, metrics = resumir_cves(r'''$Output''')
print('=== Streaming LLM ===')
stream_to_stdout(summary, metrics)
"@
}

# ---------- GUI (default) ----------
$ranHeadless = ($Scan -or $Llm -or $LlmStream)
if ($Ui -or -not $ranHeadless) {
  # si se forzó -Ui o no se hizo nada headless, arrancar GUI
  Write-Info "Iniciando GUI…"
  & $PY main.py
}