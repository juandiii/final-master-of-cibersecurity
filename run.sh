#!/usr/bin/env bash
set -euo pipefail

have() { command -v "$1" >/dev/null 2>&1; }
log()  { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m[ERR ]\033[0m %s\n" "$*" >&2; }

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# Flags / defaults
SKIP_TK_CHECK="false"
SKIP_DOCKER_CHECK="false"
WITH_TRIVY_CHECK="false"
RUN_UI="auto"            # auto => si no hay tareas headless, abre GUI
IMAGE_TAR=""
IMAGE_NAME=""
DO_SCAN="false"
DO_LLM="false"
DO_LLM_STREAM="false"
OUT_JSON="output/result.json"

usage() {
  cat <<USAGE
Usage:
  ./run.sh [options]

General:
  --skip-tk-check         No verificar tkinter
  --skip-docker-check     No verificar Docker
  --with-trivy-check      Verificar Trivy instalado
  --ui                    Forzar iniciar GUI (Tk)

Headless (CLI):
  --image <path.tar.gz>   Ruta de la imagen Docker exportada
  --auto-load             Ejecutar 'docker load -i <image>' y detectar repo:tag
  --name <repo:tag>       Nombre de imagen (si no usas --auto-load)
  --scan                  Ejecutar 'trivy image' y guardar JSON
  --llm                   Analizar JSON con llm_analyzer (resumen + LLM)
  --output <file>         Archivo de salida JSON (default: output/result.json)

Ejemplos:
  # GUI por defecto
  ./run.sh

  # Flujo headless completo
  ./run.sh --image ./ubuntu.tar.gz --auto-load --scan --llm

  # Solo escanear usando una imagen ya existente por nombre
  ./run.sh --name ubuntu:latest --scan --output output/ubuntu.json
USAGE
}

# Parse flags
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-tk-check)       SKIP_TK_CHECK="true"; shift ;;
    --skip-docker-check)   SKIP_DOCKER_CHECK="true"; shift ;;
    --with-trivy-check)    WITH_TRIVY_CHECK="true"; shift ;;
    --ui)                  RUN_UI="true"; shift ;;
    --image)               IMAGE_TAR="${2:-}"; shift 2 ;;
    --auto-load)           AUTO_LOAD="true"; shift ;;
    --name)                IMAGE_NAME="${2:-}"; shift 2 ;;
    --scan)                DO_SCAN="true"; RUN_UI="false"; shift ;;
    --llm)                 DO_LLM="true"; RUN_UI="false"; shift ;;
    --llm-stream)          DO_LLM_STREAM="true"; RUN_UI="false"; shift ;;
    --output)              OUT_JSON="${2:-}"; shift 2 ;;
    -h|--help)             usage; exit 0 ;;
    *)                     warn "Flag desconocido: $1"; shift ;;
  esac
done

# Cargar .env si existe
if [[ -f .env ]]; then
  log "Cargando variables de entorno desde .env"
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

# Python / venv
PY="./.venv/bin/python"
if [[ ! -x "$PY" ]]; then
  if have python3; then PY="python3"
  elif have python; then PY="python"
  else
    err "Python no está instalado."
    exit 1
  fi

  warn "No hay .venv. Creando virtualenv e instalando dependencias…"
  "$PY" -m venv .venv
  # shellcheck disable=SC1091
  source .venv/bin/activate
  python -m pip install -U pip setuptools wheel

  if [[ -f requirements.txt ]]; then
    pip install -r requirements.txt
  else
    # deps mínimas
    pip install 'openai==1.*'
  fi

  PY="./.venv/bin/python"
else
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

# Checks
if [[ "$SKIP_TK_CHECK" != "true" ]]; then
  log "Verificando tkinter…"
  "$PY" - <<'PY'
try:
    import tkinter as tk
    r = tk.Tk(); r.withdraw(); print("tkinter OK"); r.destroy()
except Exception as e:
    raise SystemExit(f"tkinter no disponible: {e}")
PY
fi

if [[ "$SKIP_DOCKER_CHECK" != "true" ]]; then
  if ! have docker; then
    err "Docker no está en PATH."
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    err "Docker daemon no está corriendo."
    exit 1
  fi
  log "Docker OK"
fi

if [[ "$WITH_TRIVY_CHECK" == "true" || "$DO_SCAN" == "true" ]]; then
  if ! have trivy; then
    err "Trivy no encontrado. Instálalo o quita --scan / --with-trivy-check."
    exit 1
  fi
  log "Trivy OK"
fi

# Auto-load (si se pidió)
if [[ "${AUTO_LOAD:-false}" == "true" ]]; then
  if [[ -z "$IMAGE_TAR" ]]; then
    err "--auto-load requiere --image <path.tar.gz>"
    exit 1
  fi
  if [[ ! -f "$IMAGE_TAR" ]]; then
    err "No existe el archivo: $IMAGE_TAR"
    exit 1
  fi

  log "Cargando imagen: $IMAGE_TAR"
  LOAD_OUT="$(docker load -i "$IMAGE_TAR" 2>&1 | tee /dev/stderr || true)"
  # Buscar "Loaded image: <name>"
  if grep -q "Loaded image:" <<< "$LOAD_OUT"; then
    IMAGE_NAME="$(awk -F'Loaded image:' '/Loaded image:/{gsub(/^ +| +$/,"",$2); print $2}' <<< "$LOAD_OUT" | tail -n1)"
    log "Imagen detectada: $IMAGE_NAME"
  else
    warn "No se pudo detectar 'Loaded image: ...' en la salida. Debes pasar --name <repo:tag>."
  fi
fi

# Escaneo (headless)
if [[ "$DO_SCAN" == "true" ]]; then
  if [[ -z "$IMAGE_NAME" ]]; then
    err "--scan requiere --name <repo:tag> o usar --auto-load que lo detecte."
    exit 1
  fi

  mkdir -p "$(dirname "$OUT_JSON")"
  log "Escaneando imagen con Trivy: $IMAGE_NAME"
  trivy image "$IMAGE_NAME" --format json --output "$OUT_JSON"
  log "Resultado guardado en: $OUT_JSON"
fi

# LLM (headless)
if [[ "$DO_LLM" == "true" ]]; then
  if [[ ! -f "$OUT_JSON" ]]; then
    err "--llm requiere el archivo JSON (usa --scan antes) en: $OUT_JSON"
    exit 1
  fi
  if [[ -z "${OPENAPI_API_KEY:-}" ]]; then
    warn "OPENAPI_API_KEY no está definida; la llamada al LLM fallará."
  fi

  log "Ejecutando análisis LLM con llm_analyzer…"
  "$PY" - <<PY
import json, os, sys
from llm_analyzer import resumir_cves, consultar_llm

json_path = r"""$OUT_JSON"""
summary, metrics = resumir_cves(json_path)
print("\\n=== Resumen CVEs (primeras líneas) ===")
print("\\n=== Recomendaciones LLM ===")
print(consultar_llm(summary, metrics))
PY
fi


if [[ "$DO_LLM_STREAM" == "true" ]]; then
  if [[ ! -f "$OUT_JSON" ]]; then
    err "--llm-stream requiere el JSON en: $OUT_JSON (usa --scan antes)"
    exit 1
  fi
  log "LLM streaming (CLI)…"
  "$PY" - <<PY
import json
from llm_analyzer import resumir_cves, stream_to_stdout
print("=== Streaming LLM ===")
summary, metrics = resumir_cves(r"""$OUT_JSON""")
stream_to_stdout(summary, metrics)
PY
fi

# Si no hay tareas headless, iniciar la GUI (por defecto)
if [[ "$RUN_UI" == "auto" || "$RUN_UI" == "true" ]]; then
  if [[ "$RUN_UI" == "auto" && ( "$DO_SCAN" == "true" || "$DO_LLM" == "true" ) ]]; then
    # ya hicimos trabajo headless; no iniciar GUI si no se forzó --ui
    exit 0
  fi

  export PYTHONUNBUFFERED=1
  log "Iniciando GUI…"
  exec "$PY" main.py
fi