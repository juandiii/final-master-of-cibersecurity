# Escáner de Seguridad Docker con LLM

### Esta aplicación gráfica (Tkinter) permite:

1. Cargar imágenes Docker (.tar.gz)
2. Escanearlas con Trivy
3. Resumir las vulnerabilidades (CVEs)
4. Consultar recomendaciones mediante OpenAI modelo `gpt-4o-mini`


## Requisitos previos
- Python 3.9 o superior
- Docker instalado y en funcionamiento
- Trivy instalado (https://aquasecurity.github.io/trivy/)
- Una clave de API válida de OpenAI (https://platform.openai.com/account/api-keys)
- Tener Tkinter instalado en tu sistema operativo


## Crear entorno virtual

En Linux/macOS:
```bash
pipenv shell
```

En Windows (CMD o PowerShell):
```powershell
pipenv shell
```

## Instalar dependencias

Asegúrate de estar dentro del entorno virtual y ejecuta:

`pipenv install -r requirements.txt`


### Configurar la API de OpenAI
La aplicación usa la variable de entorno `OPENAI_API_KEY`.

 En Linux/macOS:
```bash
export OPENAI_API_KEY="sk-xxxxxxxxxxxxxxxxxxxx"
```

En Windows CMD:
 ```powershell
set OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxx
```

 En PowerShell:
 ```powershell
$env:OPENAI_API_KEY="sk-xxxxxxxxxxxxxxxxxxxx"
```

 ¡No olvides reemplazar `sk-xxxxxxxx...` con tu propia API Key!

## Ejecutar la aplicación

Desde el mismo terminal (con entorno activado y clave API configurada), ejecuta:

```bash
python main.py
```

Estructura esperada

El proyecto debe tener al menos estos archivos:

- `main.py` → interfaz gráfica
- `llm_analyzer.py` → lógica del resumen y llamada al modelo
- `/output/result.json` → generado automáticamente por Trivy
- `README.md` → este documento

### Flujo de uso

1. Selecciona una imagen Docker `.tar.gz`.
2. Carga la imagen en Docker.
3. El nombre se detecta automáticamente.
4. Escanea la imagen con Trivy.
5. Se muestra un resumen de vulnerabilidades (no el JSON).
6. Haz clic en "Analizar con LLM" para obtener recomendaciones.

### Notas útiles

- El modelo utilizado es `gpt-4o-mini`, que es económico y eficiente.
- Si tienes problemas con Trivy, asegúrate de que esté en tu PATH (`trivy -v`).
- El campo de nombre de imagen no es editable manualmente: se rellena automáticamente al cargar la imagen.


## Autor
Juan Diego López – Proyecto personal para análisis de seguridad en imágenes Docker usando IA.
