from __future__ import annotations
import json, os, threading, time
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Tuple
from openai import OpenAI, RateLimitError, APIConnectionError, APIStatusError

# ======================
# Config
# ======================
MODEL_NAME = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
MAX_ITEMS = int(os.getenv("TRIVY_MAX_ITEMS", "50"))     # CVEs máximos al prompt
STREAM = os.getenv("LLM_STREAM", "false").lower() == "true"
# MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "900"))
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# Severidades ordenadas
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

# Cliente OpenAI (usa OPENAI_API_KEY)
client = OpenAI(api_key=OPENAI_API_KEY)

# ======================
# Datos / helpers
# ======================

def _read_env(env_key: str | None = None) -> Optional[int]:
    raw = os.getenv(env_key)
    if not raw or not raw.strip():
        return None  # desactivado
    try:
        val = int(raw.strip())
        return val if val > 0 else None  # 0 o negativo => desactivado
    except ValueError:
        return None

MAX_TOKENS: Optional[int] = _read_env("LLM_MAX_TOKENS")

@dataclass(frozen=True)
class CVEItem:
    id: str
    pkg: str
    severity: str
    title: str

def _severity_key(s: str) -> int:
    return SEV_ORDER.get((s or "").upper(), 0)

def _dedupe_keep_strongest(items: Iterable[CVEItem]) -> List[CVEItem]:
    """Si hay duplicados por (id,pkg), conserva la severidad más alta."""
    best: Dict[Tuple[str, str], CVEItem] = {}
    for it in items:
        k = (it.id, it.pkg)
        prev = best.get(k)
        if not prev or _severity_key(it.severity) > _severity_key(prev.severity):
            best[k] = it
    return list(best.values())

def _counts_by_sev(items: Iterable[CVEItem]) -> Dict[str, int]:
    c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for it in items:
        c[it.severity.upper()] = c.get(it.severity.upper(), 0) + 1
    return c

# ======================
# Resumen de Trivy
# ======================
def resumir_cves(trivy_result_path: str, max_items: int = MAX_ITEMS) -> Tuple[str, Dict[str, int]]:
    """
    Lee result.json de Trivy y devuelve:
      - texto breve por línea: "<CVE> | <pkg> | <SEV> | <title>"
      - métricas por severidad
    """
    try:
        with open(trivy_result_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return "Error al leer el archivo de resultados.", {"error": 1}

    raw: List[CVEItem] = []
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            raw.append(
                CVEItem(
                    id=str(vuln.get("VulnerabilityID", "")),
                    pkg=str(vuln.get("PkgName", "")),
                    severity=str(vuln.get("Severity", "UNKNOWN")).upper(),
                    title=str(vuln.get("Title", "")),
                )
            )

    if not raw:
        return "No se encontraron vulnerabilidades en la imagen.", {"total": 0}

    # dedupe + ordenar por severidad (desc) y luego por id
    items = _dedupe_keep_strongest(raw)
    items.sort(key=lambda x: (_severity_key(x.severity), x.id), reverse=True)

    metrics = _counts_by_sev(items)
    total = len(items)
    metrics["total"] = total

    # Limitar para el prompt
    sel = items[: max_items]
    lines = [f"- {it.id} | {it.pkg} | {it.severity} | {it.title}" for it in sel]
    return "\n".join(lines), metrics

# ======================
# LLM
# ======================
def _build_messages(resumen_lines: str, metrics: Dict[str, int], language: str = "es") -> List[Dict[str, str]]:
    sys = (
        "Eres un analista senior de seguridad de contenedores y supply-chain. "
        "Respondes en ESPAÑOL, de forma clara, accionable y sin alucinar. "
        "No inventes CVEs, versiones ni ‘fix versions’. Si un dato falta, escribe 'DESCONOCIDO'. "
        "Tu razonamiento debe ser interno; SOLO devuelve el informe final solicitado."
    )

    user = f"""
            Analiza la siguiente imagen Docker y sus vulnerabilidades resumidas. Genera un informe breve, priorizado y accionable.

            ## Contexto

            ## Datos de entrada
            - Métricas agregadas: {json.dumps(metrics, ensure_ascii=False)}
            - CVEs (deduplicados):
            {resumen_lines}

            ## Instrucciones de salida (formato estricto)
            Entregá 1 sección: primero un informe en Markdown con el plan de acción.

            ### 1) Informe
            1. **Resumen ejecutivo.** Qué tan expuesta está la imagen y por qué.
            2. **Top hallazgos (tabla)** con columnas EXACTAS:
            CVE | Paquete | Severidad | Versión instalada | Versión fija | Explotabilidad (baja/media/alta) | Impacto en contenedor (build/runtime) | Acción sugerida
            - Si no hay versión fija, pon 'NO-FIX' y sugiere mitigación.
            3. **Plan de mitigación priorizado** (P0/P1/P2/P3) con horizontes: P0=48h, P1=7d, P2=30d, P3=backlog.
            - Prioriza por: severidad, explotabilidad, exposición (runtime vs build), disponibilidad de fix y facilidad de cambio de base image.
            4. **Hardening**: mínimos privilegios, usuario no-root, fs read-only, drop capabilities, pin de versiones, reducir superficie (multi-stage), escaneo en CI.
            5. **Riesgos residuales y próximos pasos**: qué queda pendiente y cómo monitorearlo.

            **Reglas extra:**
            - Si varias CVEs afectan al mismo paquete, agrupa la recomendación (evita repetir acciones idénticas).
            - Si la mayoría de findings son de sistema base, sugiere mover a una base ‘-slim’ o distroless equivalente.
            - Si no hay datos suficientes, dilo explícitamente (no inventes).

            Devuélvelo como ÚLTIMA línea, sin texto luego.

            ¡Importante! No incluyas comentarios ni múltiples objetos.
            """
    return [
        {"role": "system", "content": sys},
        {"role": "user", "content": user},
    ]

def consultar_llm(resumen_lines: str, metrics: Dict[str, int], meta: dict | None = None, timeout: float = 30.0) -> str:
    """
    Llama al modelo con reintentos suaves en caso de rate limit / fallos transitorios.
    """
    messages = _build_messages(resumen_lines, metrics, meta)
    backoff = 2.0

    kwargs = {
        "model": MODEL_NAME,
        "messages": messages,
        "temperature": 0.4,
        "timeout": timeout
        }

    if MAX_TOKENS is not None:
        kwargs["max_tokens"] = MAX_TOKENS

    for attempt in range(3):
        try:
            if STREAM:
                chunks = []
                with client.chat.completions.create(**kwargs) as stream:
                    for ev in stream:
                        delta = ev.choices[0].delta.content or ""
                        chunks.append(delta)
                return "".join(chunks).strip()
            else:
                resp = client.chat.completions.create(**kwargs)
                return (resp.choices[0].message.content or "").strip()
        except (RateLimitError, APIConnectionError, APIStatusError) as e:
            # backoff sencillo
            if attempt == 2:
                return f"Error al consultar el modelo (intentos agotados): {e}"
            time.sleep(backoff)
            backoff *= 2
        except Exception as e:
            return f"Error al consultar el modelo: {e}"
    return "Error desconocido al consultar el modelo."

def consultar_llm_stream(resumen_lines: str, metrics: Dict[str, int], on_delta: Callable[[str], None], timeout: float = 30.0) -> None:
    """
    Streaming token-a-token: llama on_delta(text) cada vez que llega un fragmento.
    """

    messages = _build_messages(resumen_lines, metrics)

    kwargs = {
    "model": MODEL_NAME,
    "messages": messages,
    "temperature": 0.3,
    "stream": True,
    "timeout": timeout
    }

    if MAX_TOKENS is not None:
        kwargs["max_tokens"] = MAX_TOKENS
    with client.chat.completions.create(**kwargs) as stream:
        for ev in stream:
            delta = ev.choices[0].delta.content or ""
            if delta:
                on_delta(delta)


def stream_to_stdout(summary: str, metrics: Dict[str, int]) -> None:
    """
    Versión streaming para CLI: imprime tokens inmediatamente.
    """
    def _emit(s: str):
        print(s, end="", flush=True)
    consultar_llm_stream(summary, metrics, _emit)
    print()  # salto de línea final

# ======================
# Worker en hilo
# ======================
def analizar_con_llm(trivy_json_path: str, callback: Callable[[str], None]) -> None:
    """
    Ejecuta en segundo plano. El callback recibe el string final.
    En Tkinter, llama a `root.after(0, lambda: ui_update(text))` dentro del callback para actualizar la UI.
    """
    def worker():
        try:
            resumen, metrics = resumir_cves(trivy_json_path)
            # Si no hay CVEs, igual pedimos recomendaciones generales:
            respuesta = consultar_llm(resumen, metrics)
            callback(respuesta)
        except Exception as e:
            callback(f"Error en análisis: {e}")

    t = threading.Thread(target=worker, daemon=True)
    t.start()