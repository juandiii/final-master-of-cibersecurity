import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import os
import subprocess
import json
import threading

# Importar lógica del análisis LLM desde archivo externo
from llm_analyzer import analizar_con_llm

# Crear ventana principal
ventana = tk.Tk()
ventana.title("Escáner de Seguridad Docker (con Ollama)")
ventana.geometry("800x900")
ventana.configure(bg="#f4f4f4")
ventana.resizable(False, False)

# Crear un marco central con estilo de tarjeta para contener los widgets
contenedor = tk.Frame(ventana, bg="white", bd=2, relief="groove")
contenedor.place(relx=0.5, rely=0.02, anchor="n", relwidth=0.95, relheight=0.95)


# Función para seleccionar un archivo .tar.gz desde el sistema
def seleccionar_archivo():
    archivo = filedialog.askopenfilename(
        title="Selecciona una imagen Docker .tar.gz",
        filetypes=[("Archivos tar.gz", "*.tar.gz")]
    )
    if archivo:
        ruta_entry.delete(0, tk.END)
        ruta_entry.insert(0, archivo)


# Función para cargar la imagen en Docker y detectar su nombre automáticamente
def cargar_imagen():
    global imagen_cargada
    ruta = ruta_entry.get()
    if not os.path.exists(ruta):
        messagebox.showerror("Error", "Archivo no encontrado.")
        return
    try:
        resultado = subprocess.run(
            ["docker", "load", "-i", ruta],
            capture_output=True,
            text=True,
            check=True
        )
        salida = resultado.stdout.strip()
        print("[DEBUG] docker load output:", salida)
# Buscar nombre de la imagen cargada desde la salida del comando
        for linea in salida.splitlines():
            if "Loaded image:" in linea:
                imagen_cargada = linea.split("Loaded image:")[1].strip()
                break

        if imagen_cargada:
            nombre_entry.delete(0, tk.END)
            nombre_entry.insert(0, imagen_cargada)  # Mostrar en el campo
            messagebox.showinfo("Carga exitosa", f"Imagen cargada: {imagen_cargada}")
        else:
            messagebox.showwarning("Carga incompleta", "Imagen cargada, pero no se detectó el nombre.")

    except Exception as e:
        messagebox.showerror("Error al cargar imagen", str(e))


# Escanear la imagen Docker con Trivy y mostrar un resumen de vulnerabilidades
def escanear_imagen():
    global imagen_cargada
    nombre = nombre_entry.get()
    if not nombre:
        messagebox.showerror("Error", "No se detectó el nombre de la imagen cargada.")
        return
    try:
        os.makedirs("output", exist_ok=True)
        ruta_salida = os.path.join("output", "result.json")
        comando = ["trivy", "image", nombre, "--format", "json", "--output", ruta_salida]
        subprocess.run(comando, check=True)
        messagebox.showinfo("Escaneo completo", "Análisis terminado. Mostrando resumen...")

       # Importar función para resumir los CVEs y mostrarlo en el área de texto superior
        from llm_analyzer import resumir_cves
        resumen = resumir_cves(ruta_salida)

        texto.delete(1.0, tk.END)
        texto.insert(tk.END, resumen)

    except Exception as e:
        messagebox.showerror("Error al ejecutar Trivy", str(e))


# Función auxiliar para mostrar el JSON completo (no se usa en flujo principal)
def mostrar_resultado(json_path):
    try:
        with open(json_path, "r") as f:
            datos = json.load(f)
            texto.delete(1.0, tk.END)
            texto.insert(tk.END, json.dumps(datos, indent=2))
    except:
        texto.insert(tk.END, "No se pudo leer el resultado.")

# Ejecutar análisis con el modelo LLM (OpenAI) en segundo plano
def ejecutar_llm():
    json_path = os.path.join("output", "result.json")
    if not os.path.exists(json_path):
        messagebox.showerror("Error", "Primero debes escanear una imagen con Trivy.")
        return

    texto_llm.delete(1.0, tk.END)
    texto_llm.insert(tk.END, "Consultando al modelo LLM...\n")
    ventana.update()
   # Crear hilo para no congelar la interfaz mientras se consulta el modelo
    def worker():
        try:
            from llm_analyzer import resumir_cves, consultar_llm

            
            resumen = resumir_cves(json_path) # Obtener resumen del archivo de resultados

            respuesta = consultar_llm(resumen)  # Enviar resumen al LLM
            texto_llm.delete(1.0, tk.END)
            texto_llm.insert(tk.END, respuesta)

        except Exception as e:
            texto_llm.delete(1.0, tk.END)
            texto_llm.insert(tk.END, f"Error en análisis: {e}")

    threading.Thread(target=worker).start()


# === INTERFAZ ===

# Fondo gris claro
ventana.configure(bg="#f4f4f4")

# Contenedor blanco tipo tarjeta
frame = tk.Frame(ventana, bg="white", bd=2, relief="groove")
frame.place(relx=0.5, rely=0.02, anchor="n", relwidth=0.95, relheight=0.95)

# Entrada de ruta del archivo

tk.Label(frame, text="Ruta de imagen .tar.gz:", bg="white", font=("Arial", 11)).pack(pady=(20, 0))
ruta_entry = tk.Entry(frame, width=70, font=("Arial", 10), relief="sunken", bd=1, bg="white")
ruta_entry.pack(pady=(0, 10))


# Botones para seleccionar y cargar imagen

tk.Button(frame, text="Seleccionar archivo", command=seleccionar_archivo, font=("Arial", 10), width=30).pack(pady=5)
tk.Button(frame, text="Cargar imagen a Docker", command=cargar_imagen, font=("Arial", 10), width=30).pack(pady=5)

# Campo que mostrará automáticamente el nombre de la imagen cargada

tk.Label(frame, text="Nombre de la imagen cargada (ej: ubuntu:latest):", bg="white", font=("Arial", 11)).pack(pady=(20, 0))
nombre_entry = tk.Entry(frame, width=40, font=("Arial", 10), relief="sunken", bd=1, bg="white")
nombre_entry.pack(pady=(0, 10))

# Botón para escanear la imagen con Trivy

tk.Button(frame, text="Escanear con Trivy", command=escanear_imagen, font=("Arial", 10), width=30).pack(pady=10)

# Área donde se muestra el resumen de CVEs

tk.Label(frame, text="Resultado del análisis de Trivy:", bg="white", font=("Arial", 11)).pack()
texto = scrolledtext.ScrolledText(frame, width=85, height=15, font=("Courier", 10), relief="sunken", bd=1, bg="white")
texto.pack(padx=10, pady=5)

# Botón para analizar el resumen con el modelo LLM

tk.Button(frame, text="Analizar con LLM", command=ejecutar_llm, bg="#d0f0c0", font=("Arial", 11, "bold"), width=25, height=2).pack(pady=15)

# Área donde se muestra la respuesta del modelo

tk.Label(frame, text="Respuesta del modelo LLM (Recomendaciones):", bg="white", font=("Arial", 11)).pack()
texto_llm = scrolledtext.ScrolledText(frame, width=85, height=10, font=("Courier", 10), relief="sunken", bd=1, bg="#f8f8f8")
texto_llm.pack(padx=10, pady=(5, 20))

# Ejecutar el bucle principal de la interfaz
ventana.mainloop()
