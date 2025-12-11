# Escáner de Seguridad Docker con LLM

### Esta aplicación gráfica (Tkinter) permite:

1. Cargar imágenes Docker (.tar.gz)
2. Escanearlas con Trivy
3. Resumir las vulnerabilidades (CVEs)
4. Consultar recomendaciones mediante `OpenAI` modelo `gpt-4o-mini`


## Requisitos previos
- Python 3.9 o superior
- Docker instalado y en funcionamiento
- Trivy instalado (https://aquasecurity.github.io/trivy/)
- Una clave de API válida de OpenAI (https://platform.openai.com/account/api-keys)
- Tkinter (para GUI):
	* Ubuntu/Debian: `sudo apt-get install -y python3-tk`
	* Fedora: `sudo dnf install -y python3-tkinter`
	* macOS: suele venir con Python.org; si falla, instale `python-tk/tcl-tk` y recree el venv.


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


## Pruebas de ejecucción rápido (Usando modo CLI)

Variables de entorno (`.env` recomendado)
---

Cree un archivo `.env` en la raíz del proyecto (opcional pero recomendado):

```env
# LLM
OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxx
OPENAI_MODEL=gpt-4o-mini

# Límite de CVEs a enviar al prompt (por defecto 50)
TRIVY_MAX_ITEMS=50

# Límite de tokens (si no define, no se envía)
LLM_MAX_TOKENS=900
```

1) Usando un archivo *.tar.gz y detección autmatica del nombre de imagen Docker

**bash: (linux/MacOS)**
```bash
./run.sh --image ./imagenes/ubuntu_latest.tar.gz --auto-load --scan --llm
```

**PowerShell:**
```powershell
pwsh ./run.ps1 -Image .\imagenes\ubuntu_latest.tar.gz -AutoLoad -Scan -Llm
```

2) Escanear una imagen existente por repo:tag

**bash: (linux/MacOS)**
```bash
./run.sh --name ubuntu:latest --scan --llm --skip-tk-check
```

**PowerShell:**
```powershell
pwsh ./run.ps1 -Name ubuntu:latest -Scan -Llm
```

3) Streaming del LLM (Token a Token - Tiempo Real)

**bash: (linux/MacOS)**
```bash
./run.sh --name ubuntu:latest --scan --llm-stream --skip-tk-check
```

**PowerShell:**
```powershell
pwsh ./run.ps1 -Name ubuntu:latest -Scan -LlmStream
```

Flag
---

**bash:**
```bash
./run.sh --help
```

**PowerShell:**
```powershell
pwsh ./run.ps1 -Help
```

### Flags principales

- `--image <path.tar[.gz]>` / `-Image`: ruta a export de imagen.
- `--auto-load` / `-AutoLoad`: hace `docker load -i <image>` y detecta `repo:tag`.
- `--name <repo:tag>` / `-Name`: usar imagen existente en host.
- `--scan` / `-Scan`: escanea con Trivy y guarda JSON.
- `--llm` / `-Llm`: procesa el JSON con el LLM (no streaming).
- `--llm-stream` / `-LlmStream`: salida del LLM en streaming (CLI).
- `--output <file>` / `-Output`: ruta del JSON de salida (por defecto `output/result.json`).
- `--with-trivy-check` / `-WithTrivyCheck`: verifica que Trivy esté instalado.
- `--skip-tk-check` / `-SkipTkCheck`: no valida tkinter.
- `--skip-docker-check` / `-SkipDockerCheck`: no valida Docker.
- `--ui` / `-Ui`: fuerza GUI.

## Ejemplo reproducible para el tribunal

1. **Preparar una imagen con vulnerabilidades** (ejemplo):

```bash
docker pull php:7.4-apache
docker save -o php-7.4-apache.tar php:7.4-apache
```

2. **Ejecutar GUI**:

```bash
./run.sh
# (Windows) pwsh ./run.ps1
```

- Seleccionar `php-7.4-apache.tar`
- Cargar → Escanear → Analizar con LLM

3. **O flujo CLI directo**:

```bash
./run.sh --image ./php-7.4-apache.tar --auto-load --scan --llm --skip-tk-check
# (Windows) pwsh ./run.ps1 -Image .\php-7.4-apache.tar -AutoLoad -Scan -Llm
```

---

## Archivos importantes

- `main.py` → GUI Tkinter.
- `llm_analyzer.py` → parsing Trivy + prompt LLM (con soporte streaming).
- `run.sh` / `run.ps1` → scripts de orquestación.
- `output/result.json` → resultado del escaneo.

---

## Solución de problemas

- **`OpenAIError: The api_key client option must be set…`**
  Falta `OPENAI_API_KEY`. Defínalo en `.env` o en el entorno.

- **`tkinter no disponible`**
  Instale `python3-tk` (Linux) o `tcl-tk`/`python-tk` (macOS) y **recree el venv**.

- **`Docker daemon no está corriendo`**
  Abra Docker Desktop o inicie el servicio (`sudo systemctl start docker`).

- **Trivy no encontrado**
  Instálelo y expórtelo al `PATH`. Ejemplo Ubuntu:
  ```bash
  sudo apt-get install -y wget
  wget https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.56.2_Linux-64bit.deb
  sudo dpkg -i trivy_0.56.2_Linux-64bit.deb
  ```

- **Streaming no imprime nada**
  Verifique el flag activado `--llm-stream`

---

## Privacidad

- El escaneo de Trivy se ejecuta **localmente**.
- El contenido enviado al LLM depende de su configuración:
  - **OpenAI**: los resúmenes de CVEs (no logs completos) viajan a la API.

---


## Autor
Juan Diego López – Proyecto personal para análisis de seguridad en imágenes Docker usando IA.
