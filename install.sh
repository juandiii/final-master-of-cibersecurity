#!/usr/bin/env bash
set -euo pipefail

# ----------------------------
# helpers
# ----------------------------
have() { command -v "$1" >/dev/null 2>&1; }
log()  { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m[ERR ]\033[0m %s\n" "$*" >&2; }

WITH_TRIVY="false"
for arg in "$@"; do
  case "$arg" in
    --with-trivy) WITH_TRIVY="true" ;;
    *) warn "flag desconocido: $arg" ;;
  esac
done

OS="$(uname -s)"

# ----------------------------
# installers
# ----------------------------
install_mac() {
  log "Detectado macOS"
  if ! have python3; then
    if have brew; then
      log "Instalando Python con Homebrew…"
      brew update
      brew install python
    else
      warn "Homebrew no encontrado. Instala Python desde https://www.python.org/downloads/macos/ (incluye Tk)."
    fi
  fi

  # Tk en macOS: Python oficial ya trae Tk. Con Homebrew suele funcionar sin pasos extra.
  if have brew; then
    # tcl-tk puede ayudar en algunas Macs antiguas
    brew list tcl-tk >/dev/null 2>&1 || brew install tcl-tk || true
  fi

  if [ "$WITH_TRIVY" = "true" ]; then
    if have brew; then
      log "Instalando Trivy…"
      brew install trivy || warn "No se pudo instalar Trivy con brew."
    else
      warn "Instala Trivy manualmente: https://aquasecurity.github.io/trivy/v0.55/getting-started/installation/"
    fi
  fi
}

install_linux() {
  log "Detectado Linux"
  if have apt-get; then
    sudo apt-get update -y
    sudo apt-get install -y python3 python3-venv python3-pip python3-tk
    [ "$WITH_TRIVY" = "true" ] && sudo apt-get install -y trivy || true
  elif have dnf; then
    sudo dnf install -y python3 python3-pip python3-tkinter
    if [ "$WITH_TRIVY" = "true" ]; then
      sudo dnf install -y trivy || warn "Trivy no disponible en tu repo dnf."
    fi
  elif have pacman; then
    sudo pacman -Sy --noconfirm python tk
    if [ "$WITH_TRIVY" = "true" ]; then
      sudo pacman -Sy --noconfirm trivy || warn "Trivy no disponible en pacman."
    fi
  else
    warn "No se detectó gestor de paquetes soportado. Instala Python 3 + Tk manualmente."
  fi
}

# ----------------------------
# main
# ----------------------------
case "$OS" in
  Darwin) install_mac ;;
  Linux)  install_linux ;;
  MINGW*|MSYS*|CYGWIN*)
    err "Windows detectado. Usa script.ps1 (PowerShell)."
    exit 1
    ;;
  *)
    warn "SO no reconocido: $OS. Continuo si ya tienes Python 3 y Tk."
    ;;
esac

# Selección de python
PY="python3"
have "$PY" || PY="python"
have "$PY" || { err "Python no encontrado. Instálalo e intenta de nuevo."; exit 1; }

log "Creando entorno virtual .venv…"
"$PY" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

log "Actualizando pip/setuptools/wheel…"
python -m pip install -U pip setuptools wheel

if [ -f requirements.txt ]; then
  log "Instalando dependencias desde requirements.txt…"
  pip install -r requirements.txt
else
  log "Instalando dependencias mínimas…"
  pip install 'openai==1.*'
fi

log "Verificando tkinter…"
python - <<'PY'
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

log "Listo ✅"
echo
echo "Siguientes pasos:"
echo "  1) Exporta tu API key:  export OPENAI_API_KEY=sk-xxxx"
echo "  2) Ejecuta la app:      python main.py"
echo