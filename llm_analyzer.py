import json
import threading
import os
from openai import OpenAI

# Inicializa el cliente de OpenAI usando la clave de entorno
client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")  
)
# Función para resumir vulnerabilidades desde el JSON generado por Trivy
def resumir_cves(trivy_result_path):
    """
    Lee el archivo result.json generado por Trivy y extrae un resumen
    de vulnerabilidades: ID, paquete afectado, severidad y título.
    """
    try:
        with open(trivy_result_path, "r") as f:
            data = json.load(f)

        resumen = []
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                resumen.append(
                    f"- {vuln.get('VulnerabilityID')} | {vuln.get('PkgName')} | "
                    f"{vuln.get('Severity')} | {vuln.get('Title', '')}"
                )

        if not resumen:
            return "No se encontraron vulnerabilidades en la imagen."

        return "\n".join(resumen[:20])  

    except Exception as e:
        print("[ERROR] Al resumir CVEs:", e)
        return "Error al leer el archivo de resultados."

# Función para consultar el modelo LLM con el resumen de vulnerabilidades
def consultar_llm(texto_resumen):
    """
    Envía el resumen al modelo LLM de DeepSeek y devuelve recomendaciones.
    """
    prompt = (
        "Analiza la siguiente lista de vulnerabilidades encontradas en una imagen Docker. "
        "Para cada una, proporciona una breve explicación del riesgo y, si es posible, "
        "una recomendación de mitigación o actualización.\n\n"
        f"{texto_resumen}\n\n"
        "Devuelve el análisis en formato claro y estructurado."
    )

    print("[DEBUG] Enviando prompt al LLM. Longitud:", len(prompt))

    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.4,
            max_tokens=700
        )

        print("[DEBUG] Respuesta recibida del LLM.")
        return response.choices[0].message.content.strip()

    except Exception as e:
        print("[DEBUG] Excepción en consultar_llm:", e)
        return f"Error al consultar el modelo: {e}"

# Función que ejecuta todo el análisis en segundo plano con callback
def analizar_con_llm(trivy_json_path, callback):
    """
    Ejecuta el análisis en segundo plano para evitar que la UI se congele.
    Usa callback para devolver el resultado a la interfaz.
    """
    def worker():
        try:
            print("[DEBUG] Iniciando análisis LLM en hilo...")
            resumen = resumir_cves(trivy_json_path)
            print("[DEBUG] Resumen generado. Longitud:", len(resumen))
            respuesta = consultar_llm(resumen)
            print("[DEBUG] Análisis completado. Enviando al callback.")
            callback(respuesta)
        except Exception as e:
            print("[ERROR] En analizar_con_llm:", e)
            callback(f"Error en análisis: {e}")
    # Ejecuta el proceso en un nuevo hilo
    threading.Thread(target=worker).start()
