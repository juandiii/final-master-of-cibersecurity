===============================
Escáner de Seguridad Docker con LLM
===============================

Esta aplicación gráfica (Tkinter) permite:

 Cargar imágenes Docker (.tar.gz)
 Escanearlas con Trivy
 Resumir las vulnerabilidades (CVEs)
Consultar recomendaciones mediante OpenAI GPT-3.5 Turbo

-------------------------------
Requisitos previos
-------------------------------
- Python 3.8 o superior
- Docker instalado y en funcionamiento
- Trivy instalado (https://aquasecurity.github.io/trivy/)
- Una clave de API válida de OpenAI (https://platform.openai.com/account/api-keys)

-------------------------------
 Crear entorno virtual
-------------------------------

 En Linux/macOS:
python3 -m venv venv
source venv/bin/activate

En Windows (CMD o PowerShell):
python -m venv venv
venv\Scripts\activate

-------------------------------
Instalar dependencias
-------------------------------
Asegúrate de estar dentro del entorno virtual y ejecuta:

pip install openai

-------------------------------
 Configurar la API de OpenAI
-------------------------------
La aplicación usa la variable de entorno `OPENAI_API_KEY`.

 En Linux/macOS:
export OPENAI_API_KEY="sk-xxxxxxxxxxxxxxxxxxxx"

 En Windows CMD:
set OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxx

 En PowerShell:
$env:OPENAI_API_KEY="sk-xxxxxxxxxxxxxxxxxxxx"

 ¡No olvides reemplazar `sk-xxxxxxxx...` con tu propia API Key!

-------------------------------
 Ejecutar la aplicación
-------------------------------

Desde el mismo terminal (con entorno activado y clave API configurada), ejecuta:

python main.py

-------------------------------
Estructura esperada
-------------------------------

El proyecto debe tener al menos estos archivos:

- `main.py` → interfaz gráfica
- `llm_analyzer.py` → lógica del resumen y llamada al modelo
- `/output/result.json` → generado automáticamente por Trivy
- `README.txt` → este documento

-------------------------------
Flujo de uso
-------------------------------

1. Selecciona una imagen Docker `.tar.gz`.
2. Carga la imagen en Docker.
3. El nombre se detecta automáticamente.
4. Escanea la imagen con Trivy.
5. Se muestra un resumen de vulnerabilidades (no el JSON).
6. Haz clic en "Analizar con LLM" para obtener recomendaciones.

-------------------------------
 Notas útiles
-------------------------------

- El modelo utilizado es `gpt-3.5-turbo`, que es económico y eficiente.
- Si tienes problemas con Trivy, asegúrate de que esté en tu PATH (`trivy -v`).
- El campo de nombre de imagen no es editable manualmente: se rellena automáticamente al cargar la imagen.

-------------------------------
 Autor
-------------------------------
Juan Diego López – Proyecto personal para análisis de seguridad en imágenes Docker usando IA.
