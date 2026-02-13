# DarkmLens v4.2 (Darkmoon)

**DarkmLens** es una herramienta de **análisis pasivo defensivo** para generar un **reporte de exposición pública** de una aplicación web que tú controles o para la cual tengas **autorización explícita** (auditoría, pentest autorizado, validación interna, etc.).

La herramienta:
- Detecta tecnologías (opcional con Wappalyzer).
- Descubre rutas internas (DOM + heurística sobre JS/CSS + navegación JS).
- Infiere requests a endpoints (fetch/axios) y extrae hints de **métodos**, **params** y **posibles body keys**.
- Identifica indicios de backend/config (headers, cookies, CloudFront, Firebase, Cognito, Sentry, etc.).
- Puede hacer crawling same-origin.
- Puede tomar screenshots con Playwright.
- Puede hacer “AuthZ Audit” (visitar rutas detectadas y clasificar **con acceso / sin acceso**).
- Genera un reporte **HTML bonito** y un `results.json` completo.

---

## ⚠️ Uso responsable (obligatorio)

Este proyecto debe usarse **solo** en:
- Activos que sean tuyos, de tu organización, o
- Sistemas donde exista **permiso explícito por escrito** para realizar pruebas.

No uses esta herramienta para:
- Escanear sitios de terceros sin autorización.
- Intentar evadir controles, autenticación o explotación.
- Recolectar datos sensibles.

**El autor/usuario final es responsable del uso y de cumplir la ley, políticas internas y acuerdos de autorización.**

---

## Requisitos

- Python 3.10+ recomendado (funciona en 3.11/3.12 también).
- `pip` habilitado.
- **Pipenv** (obligatorio para el flujo recomendado).
- (Opcional) `playwright` para screenshots.
- (Opcional) `Wappalyzer` (librería Python) para detección de tecnologías.
- (Opcional) `ollama` instalado localmente si quieres resumen por IA.

---

## Instalación de Pipenv

### Windows (PowerShell o CMD)

1) Verifica Python:
```bash
py --version
py -m pip --version
```

2) Instala Pipenv:
```bash
py -m pip install --user pipenv
```

3) Si `pipenv` no aparece, agrega el directorio Scripts al PATH (típico):
- `C:\Users\<TU_USUARIO>\AppData\Roaming\Python\Python3x\Scripts\`

Luego abre una terminal nueva y prueba:
```bash
pipenv --version
```

---

### macOS

Opción A (recomendada): con Homebrew
```bash
brew install pipenv
pipenv --version
```

Opción B (pip)
```bash
python3 -m pip install --user pipenv
pipenv --version
```

---

### Linux

Opción A (pip)
```bash
python3 -m pip install --user pipenv
pipenv --version
```

Si no se reconoce `pipenv`, agrega `~/.local/bin` al PATH:
```bash
export PATH="$HOME/.local/bin:$PATH"
```
(idealmente ponlo en tu `~/.bashrc` o `~/.zshrc`)

---

## Instalación del proyecto

En la carpeta del proyecto (donde está `app.py`):

1) Crear entorno e instalar dependencias:
```bash
pipenv install
```

2) (Opcional) Instalar extras:

- Playwright para screenshots:
```bash
pipenv install playwright
pipenv run playwright install chromium
```

- Wappalyzer (si lo usas):
```bash
pipenv install python-Wappalyzer
```

> Nota: el nombre del paquete puede variar según tu elección/compatibilidad. Si ya tienes una lib que provee `from Wappalyzer import Wappalyzer, WebPage`, instala esa.

---

## Cómo ejecutar

Ejemplo mínimo:
```bash
pipenv run python app.py https://example.com --out out/example
```

---

## Parámetros principales (CLI)

- `--out out/carpeta`  
  Carpeta de salida del reporte.

- `--max-assets 120`  
  Máximo de assets same-origin a descargar/analizar (JS/CSS).

- `--max-maps 20`  
  Máximo de sourcemaps a descargar (si se detectan).

- `--timeout 15`  
  Timeout por request (segundos).

- `--sleep 0.03`  
  Pausa entre requests (reduce carga / rate-limit).

- `--no-screenshot`  
  Deshabilita screenshots (no requiere Playwright).

- `--no-crawl`  
  Deshabilita crawling same-origin.

- `--max-pages 25` y `--max-depth 2`  
  Control del crawling.

---

## Headers para crawling autenticado (opcional)

Puedes pasar headers manuales:
```bash
pipenv run python app.py https://miapp.com --header "Cookie: session=XXXX" --header "X-Token: ABC" --out out/miapp
```

O desde archivo JSON:
```bash
pipenv run python app.py https://miapp.com --headers-json headers.json --out out/miapp
```

También bearer:
```bash
pipenv run python app.py https://miapp.com --bearer "TOKEN_AQUI" --out out/miapp
```

---

## AuthZ Audit (clasifica rutas “con acceso / sin acceso”)

Activa auditoría de rutas detectadas:
```bash
pipenv run python app.py https://miapp.com --audit-authz --out out/miapp
```

Limitar número de rutas a probar:
```bash
pipenv run python app.py https://miapp.com --audit-authz --authz-max-routes 200 --out out/miapp
```

Alias equivalente (si lo usas así):
```bash
pipenv run python app.py https://miapp.com --audit-authz --audit-authz-limit 200 --out out/miapp
```

Evitar screenshots en AuthZ audit:
```bash
pipenv run python app.py https://miapp.com --audit-authz --authz-no-screenshot-all --out out/miapp
```

Incluir snippet de respuesta (útil para triage, con cuidado):
```bash
pipenv run python app.py https://miapp.com --audit-authz --authz-show-response --authz-response-chars 900 --out out/miapp
```

---

## Probe GET (sondeo “seguro-ish”)

Sondea algunos endpoints inferidos con **GET** (same-origin) para ver status/CT:
```bash
pipenv run python app.py https://miapp.com --probe-get --out out/miapp
```

> Nota: esto hace requests adicionales. Úsalo solo cuando esté autorizado y con límites razonables.

---

## Resumen por IA local (Ollama)

Si tienes `ollama` instalado y quieres resúmenes cortos por ruta (AuthZ audit):
```bash
pipenv run python app.py https://miapp.com --audit-authz --ai-ollama --ai-model llama3.1:8b --out out/miapp
```

Si `ollama` no está disponible, la herramienta cae a resumen heurístico (no queda en blanco).

---

## Salida generada

Dentro de `--out` se crean:
- `index.html` → reporte visual (dashboard).
- `results.json` → datos completos en JSON.
- `report.template.html` → template editable (si quieres personalizar el reporte).
- `routes/*.txt` → bodies guardados (si `--no-save-bodies` no se usó).
- `screens/*.png` → screenshots (si Playwright está disponible y no deshabilitaste).

---

## Notas de seguridad y privacidad

- Si pasas headers de sesión/cookies, pueden reflejarse en requests. **No compartas** reportes públicamente si contienen información sensible.
- `routes/*.txt` puede contener HTML/JSON con datos internos, tokens o información de sesión dependiendo del target.
- Usa `--no-save-bodies` si no quieres persistir contenido de rutas.

---

## Troubleshooting

**1) “Playwright no instalado: sin screenshots.”**  
Instala Playwright y el navegador:
```bash
pipenv install playwright
pipenv run playwright install chromium
```

**2) “Wappalyzer no instalado (opcional).”**  
Instala la dependencia correspondiente (según tu implementación):
```bash
pipenv install python-Wappalyzer
```

**3) Error de SSL / certificados corporativos**  
En entornos con proxy/inspección TLS puede requerirse configurar certificados del sistema o variables de entorno (depende del caso).

---

## Licencia / Autoría

DarkmLens v4.2 — Darkmoon  
Uso defensivo y autorizado únicamente.
