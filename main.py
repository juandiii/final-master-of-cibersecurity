# main.py
import os
import json
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

# --- Tema del sistema (opcionalmente usar darkdetect) ---
def apply_system_theme(root: tk.Tk) -> None:
    style = ttk.Style(root)
    # intenta detectar dark/light si está darkdetect instalado
    try:
        import darkdetect
        is_dark = darkdetect.isDark()
    except Exception:
        is_dark = False  # fallback

    # Usa un tema nativo si existe
    preferred = "aqua" if root.tk.call("tk", "windowingsystem") == "aqua" else "clam"
    if preferred in style.theme_names():
        style.theme_use(preferred)

    # Ajustes mínimos de alto contraste para modo oscuro
    if is_dark:
        style.configure(".", foreground="#eaeaea", background="#1e1e1e")
        style.configure("TFrame", background="#1e1e1e")
        style.configure("TLabel", background="#1e1e1e", foreground="#eaeaea")
        style.configure("TButton", background="#2b2b2b", foreground="#ffffff")
        style.map("TButton", background=[("active", "#3a3a3a")])

# --- Lógica LLM/Trivy ---
from llm_analyzer import resumir_cves, analizar_con_llm  # <- nuevos métodos

OUTPUT_DIR = "output"
TRIVY_JSON = os.path.join(OUTPUT_DIR, "result.json")

class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Escáner de Seguridad Docker (con LLM)")
        self.root.geometry("880x900")
        self.root.minsize(880, 720)

        apply_system_theme(self.root)

        # Contenedor principal
        self.frame = ttk.Frame(self.root, padding=16)
        self.frame.pack(fill="both", expand=True)

        # Ruta del .tar.gz
        ttk.Label(self.frame, text="Ruta de imagen .tar.gz:").pack(anchor="w")
        self.var_ruta = tk.StringVar()
        row1 = ttk.Frame(self.frame)
        row1.pack(fill="x", pady=(2, 10))
        self.entry_ruta = ttk.Entry(row1, textvariable=self.var_ruta)
        self.entry_ruta.pack(side="left", fill="x", expand=True)
        ttk.Button(row1, text="Seleccionar…", command=self.seleccionar_archivo).pack(side="left", padx=(8, 0))

        # Cargar imagen a Docker
        ttk.Button(self.frame, text="Cargar imagen en Docker", command=self.cargar_imagen).pack(pady=(0, 12))

        # Nombre de la imagen detectada (repo:tag)
        ttk.Label(self.frame, text="Nombre de la imagen cargada (ej: ubuntu:latest):").pack(anchor="w")
        self.var_imagen = tk.StringVar()
        self.entry_imagen = ttk.Entry(self.frame, textvariable=self.var_imagen)
        self.entry_imagen.pack(fill="x", pady=(2, 12))

        # Escanear con Trivy
        ttk.Button(self.frame, text="Escanear con Trivy", command=self.escanear_imagen).pack(pady=(0, 8))

        ttk.Label(self.frame, text="Resumen de vulnerabilidades (Top por severidad):").pack(anchor="w")
        self.txt_resumen = ScrolledText(self.frame, height=14, wrap="word")
        self.txt_resumen.pack(fill="both", expand=False, pady=(2, 14))

        # Analizar con LLM
        self.btn_llm = ttk.Button(self.frame, text="Analizar con LLM", command=self.ejecutar_llm)
        self.btn_llm.pack(pady=(0, 8))

        ttk.Label(self.frame, text="Recomendaciones del LLM:").pack(anchor="w")
        self.txt_llm = ScrolledText(self.frame, height=12, wrap="word")
        self.txt_llm.pack(fill="both", expand=True, pady=(2, 0))

        # Ajustes mínimos para respetar tema (no fijamos bg para que herede)
        for t in (self.txt_resumen, self.txt_llm):
            t.configure(font=("Menlo" if self._is_macos() else "Courier New", 10))

    # -------- Handlers UI --------
    def seleccionar_archivo(self):
        path = filedialog.askopenfilename(
            title="Selecciona una imagen Docker .tar.gz",
            filetypes=[("Imágenes Docker exportadas", "*.tar.gz"), ("Todos", "*.*")]
        )
        if path:
            self.var_ruta.set(path)

    def cargar_imagen(self):
        ruta = self.var_ruta.get().strip()
        if not ruta or not os.path.exists(ruta):
            messagebox.showerror("Error", "Selecciona un archivo .tar.gz válido.")
            return
        try:
            res = subprocess.run(["docker", "load", "-i", ruta], text=True, capture_output=True, check=True)
            nombre = self._extraer_nombre_imagen(res.stdout)
            if nombre:
                self.var_imagen.set(nombre)
                messagebox.showinfo("Éxito", f"Imagen cargada: {nombre}")
            else:
                messagebox.showwarning("Atención", "Se cargó la imagen, pero no se detectó el nombre.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Docker error", e.stderr or e.stdout or str(e))
        except Exception as e:
            messagebox.showerror("Error inesperado", str(e))

    def escanear_imagen(self):
        imagen = self.var_imagen.get().strip()
        if not imagen:
            messagebox.showerror("Error", "Primero carga la imagen en Docker.")
            return
        try:
            os.makedirs(OUTPUT_DIR, exist_ok=True)
            # Trivy a JSON
            cmd = ["trivy", "image", imagen, "--format", "json", "--output", TRIVY_JSON]
            subprocess.run(cmd, check=True)
            # Mostrar resumen (usa el nuevo resumir_cves -> (texto, métricas))
            resumen, metrics = resumir_cves(TRIVY_JSON)
            self._set_text(self.txt_resumen, self._resumen_con_metricas(resumen, metrics))
            messagebox.showinfo("Escaneo completo", "Trivy terminó. Se cargó el resumen arriba.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Trivy error", e.stderr or e.stdout or str(e))
        except Exception as e:
            messagebox.showerror("Error inesperado", str(e))

    def ejecutar_llm(self):
        if not os.path.exists(TRIVY_JSON):
            messagebox.showerror("Error", "Primero ejecuta el escaneo con Trivy.")
            return
        self.btn_llm.state(["disabled"])
        self._set_text(self.txt_llm, "Consultando al modelo…")
        # analizar_con_llm hace el resumen internamente y llama callback al terminar
        analizar_con_llm(TRIVY_JSON, self._ui_callback_llm)

    # -------- Helpers --------
    def _ui_callback_llm(self, text: str):
        # Asegurar actualización en el hilo de Tk
        self.root.after(0, lambda: (self._set_text(self.txt_llm, text), self.btn_llm.state(["!disabled"])))

    def _set_text(self, widget: ScrolledText, content: str):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", content.strip() + "\n")
        widget.see("end")
        widget.configure(state="normal")

    @staticmethod
    def _extraer_nombre_imagen(stdout: str) -> str | None:
        # Busca "Loaded image: repo:tag" en stdout de docker load
        for line in stdout.splitlines():
            if "Loaded image:" in line:
                return line.split("Loaded image:")[1].strip()
        return None

    @staticmethod
    def _resumen_con_metricas(resumen: str, metrics: dict) -> str:
        # Si metrics contiene totales, anteponer resumen
        if metrics and "total" in metrics:
            head = (
                f"Total: {metrics.get('total', 0)} | "
                f"CRITICAL: {metrics.get('CRITICAL', 0)}, "
                f"HIGH: {metrics.get('HIGH', 0)}, "
                f"MEDIUM: {metrics.get('MEDIUM', 0)}, "
                f"LOW: {metrics.get('LOW', 0)}\n\n"
            )
            return head + resumen
        return resumen

    @staticmethod
    def _is_macos() -> bool:
        try:
            import platform
            return platform.system() == "Darwin"
        except Exception:
            return False

def main():
    root = tk.Tk()
    App(root)
    root.mainloop()

if __name__ == "__main__":
    main()