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
OPENAI_API_KEY = os.getenv("OPENAPI_API_KEY", "")

# Severidades ordenadas
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

# Cliente OpenAI (usa OPENAI_API_KEY)
client = OpenAI(api_key=OPENAI_API_KEY)

# ======================
# Datos / helpers
# ======================
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
        "Eres un analista de seguridad de contenedores. "
        "Responde en español, claro y accionable. "
        "No inventes CVEs; si faltan datos, dilo."
    )
    user = (
        "Analiza esta lista resumida de vulnerabilidades de una imagen Docker.\n"
        "Devuélveme un informe breve con este formato:\n"
        "1) Resumen (1-2 párrafos)\n"
        "2) Top hallazgos (tabla: CVE | Paquete | Severidad | Acción sugerida)\n"
        "3) Plan de mitigación por prioridad (pasos concretos)\n"
        "4) Riesgos residuales y próximos pasos\n\n"
        f"Métricas: {json.dumps(metrics, ensure_ascii=False)}\n"
        f"CVEs:\n{resumen_lines}"
    )
    return [
        {"role": "system", "content": sys},
        {"role": "user", "content": user},
    ]

def consultar_llm(resumen_lines: str, metrics: Dict[str, int], timeout: float = 30.0) -> str:
    """
    Llama al modelo con reintentos suaves en caso de rate limit / fallos transitorios.
    """
    messages = _build_messages(resumen_lines, metrics)
    backoff = 2.0
    for attempt in range(3):
        try:
            if STREAM:
                chunks = []
                with client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=messages,
                    temperature=0.3,
                    max_tokens=900,
                    stream=True,
                    timeout=timeout,
                ) as stream:
                    for ev in stream:
                        delta = ev.choices[0].delta.content or ""
                        chunks.append(delta)
                return "".join(chunks).strip()
            else:
                resp = client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=messages,
                    temperature=0.3,
                    max_tokens=900,
                    timeout=timeout,
                )
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