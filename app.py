#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import re
import json
import time
import argparse
import hashlib
import warnings
import threading
import queue
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
import urllib3
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed

# Wappalyzer (opcional)
try:
    from Wappalyzer import Wappalyzer, WebPage  # type: ignore
    HAS_WAPPALYZER = True
except Exception:
    HAS_WAPPALYZER = False

init(autoreset=True)

# Silence urllib3 InsecureRequestWarning (because verify=False is used)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =============================
# Utils
# =============================
def safe_mkdir(path: str):
    os.makedirs(path, exist_ok=True)

def uniq_list(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out

def same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)

def normalize_url(u: str) -> str:
    """Normalize URL: remove fragment, sort query params."""
    try:
        p = urlparse(u)
        q = parse_qs(p.query, keep_blank_values=True)
        items = []
        for k in sorted(q.keys()):
            for v in sorted(q[k]):
                items.append((k, v))
        new_q = urlencode(items, doseq=True)
        return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, new_q, ""))  # no fragment
    except Exception:
        return u

def line_number_from_index(text: str, idx: int) -> int:
    return text.count("\n", 0, max(0, idx)) + 1

def summarize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    keep = [
        "server", "via", "x-cache", "x-powered-by",
        "x-amz-cf-id", "x-amz-cf-pop",
        "content-security-policy", "strict-transport-security",
        "x-frame-options", "x-content-type-options",
        "referrer-policy", "permissions-policy",
        "set-cookie",
        "location",
    ]
    out = {}
    for k, v in headers.items():
        if k.lower() in keep:
            out[k] = v
    return out

def extract_query_params(url: str) -> List[str]:
    try:
        q = parse_qs(urlparse(url).query)
        return sorted(list(q.keys()))
    except Exception:
        return []

def cap_list(lst: List[Any], n: int) -> List[Any]:
    return lst[:n] if len(lst) > n else lst

def is_probably_text(ct: str) -> bool:
    ct = (ct or "").lower()
    return any(x in ct for x in ["text/", "application/json", "application/javascript", "application/xml", "application/xhtml+xml"])

def safe_filename(s: str, max_len: int = 140) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "_", s.strip())
    if not s:
        s = "file"
    return s[:max_len]

def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()[:10]

def read_text_file(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def write_text_file(path: str, content: str):
    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(content)


@dataclass
class FetchResult:
    url: str
    status: int
    content_type: str
    text: str
    headers: Dict[str, str]
    elapsed_ms: int


# =============================
# ReactScan Module (standalone functions)
# Detección de librerías, versiones y CVEs en aplicaciones React/Next.js
# =============================

_RS_TIMEOUT = 10
_RS_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
}
_RS_MAX_JS_FILES = 50

_RS_MINIFIED_SIGNATURES = [
    ("react", [
        r'exports\.version="(\d+\.\d+\.\d+[^"]*)"',
        r'\.version="(\d+\.\d+\.\d+[^"]*)"[,;].{0,300}createElement',
        r'createElement[^}]{0,300}\.version="(\d+\.\d+\.\d+[^"]*)"',
        r'"react"[^}]{0,100}"version":"(\d+\.\d+\.\d+[^"]*)"',
        r'version:"(\d+\.\d+\.\d+[^"]*)"[,;][^;]{0,100}createElement',
        r'\{version:"(\d+\.\d+\.\d+[^"]*)"[^}]{0,200}createElement',
    ]),
    ("react-dom", [
        r'"react-dom"[^}]{0,100}"version":"(\d+\.\d+\.\d+[^"]*)"',
        r'\.version="(\d+\.\d+\.\d+[^"]*)"[,;].{0,300}hydrate',
        r'hydrate[^;]{0,300}\.version="(\d+\.\d+\.\d+[^"]*)"',
        r'\{version:"(\d+\.\d+\.\d+[^"]*)"[^}]{0,200}hydrate',
    ]),
    ("next", [
        r'"next":"(\d+\.\d+\.\d+[^"]*)"',
        r'"next@(\d+\.\d+\.\d+[^"]*)"',
        r'next/dist[^"]{0,50}"version":"(\d+\.\d+\.\d+[^"]*)"',
        r'Next\.js\s+v?(\d+\.\d+\.\d+[a-zA-Z0-9.-]*)',
        r'"version":"(\d+\.\d+\.\d+[^"]*)"[^}]{0,50}"buildId"',
        r'__NEXT_VERSION[^"]{0,20}"(\d+\.\d+\.\d+[^"]*)"',
    ]),
    ("jquery", [
        r'jQuery\.fn\.jquery="(\d+\.\d+\.\d+[^"]*)"',
        r'jquery:"(\d+\.\d+\.\d+[^"]*)"',
        r'jQuery v(\d+\.\d+\.\d+[a-zA-Z0-9.-]*)',
        r'v(\d+\.\d+\.\d+) jQuery',
        r'"jquery","(\d+\.\d+\.\d+[^"]*)"',
    ]),
    ("lodash", [
        r'lodash[._]VERSION\s*=\s*"(\d+\.\d+\.\d+[^"]*)"',
        r'var\s+VERSION\s*=\s*"(\d+\.\d+\.\d+[^"]*)"[^;]{0,200}lodash',
        r'"lodash"[^}]{0,50}"version":"(\d+\.\d+\.\d+[^"]*)"',
    ]),
    ("axios", [
        r'"axios"[^}]{0,100}"version":"(\d+\.\d+\.\d+[^"]*)"',
        r'axios/(\d+\.\d+\.\d+[^"/ ]*)',
        r'"name":"axios","version":"(\d+\.\d+\.\d+[^"]*)"',
        r'isAxiosError[^"]{0,200}"version":"(\d+\.\d+\.\d+[^"]*)"',
    ]),
    ("moment", [
        r'moment\.version\s*=\s*"(\d+\.\d+\.\d+[^"]*)"',
        r'"moment"[^}]{0,100}"version":"(\d+\.\d+\.\d+[^"]*)"',
    ]),
    ("date-fns",             [r'"date-fns","(\d+\.\d+\.\d+[^"]*)"',
                              r'"date-fns"[^}]{0,100}"version":"(\d+\.\d+\.\d+[^"]*)"']),
    ("zustand",              [r'"zustand"[^}]{0,100}"version":"(\d+\.\d+\.\d+[^"]*)"']),
    ("jotai",                [r'"jotai"[^}]{0,100}"version":"(\d+\.\d+\.\d+[^"]*)"']),
    ("@tanstack/react-query",[r'"@tanstack/react-query"[^}]{0,100}"version":"(\d+\.\d+\.\d+[^"]*)"',
                              r'react-query[^"]{0,50}"version":"(\d+\.\d+\.\d+[^"]*)"']),
    ("tailwindcss",          [r'"tailwindcss"[^}]{0,100}"version":"(\d+\.\d+\.\d+[^"]*)"']),
    ("next-auth",            [r'"next-auth"[^}]{0,100}"version":"(\d+\.\d+\.\d+[^"]*)"']),
    ("framer-motion",        [r'"framer-motion"[^}]{0,100}"version":"(\d+\.\d+\.\d+[^"]*)"',
                              r'framer.motion[^"]{0,50}(\d+\.\d+\.\d+[^"]*)']),
    ("zod",                  [r'"zod"[^}]{0,100}"version":"(\d+\.\d+\.\d+[^"]*)"']),
    ("swr",                  [r'"swr"[^}]{0,100}"version":"(\d+\.\d+\.\d+[^"]*)"']),
    ("@mui/material",        [r'"@mui/material"[^}]{0,100}"version":"(\d+\.\d+\.\d+[^"]*)"']),
    ("@chakra-ui/react",     [r'"@chakra-ui/react"[^}]{0,100}"version":"(\d+\.\d+\.\d+[^"]*)"']),
    ("fast-xml-parser",      [r'"fast-xml-parser"[^}]{0,100}"version":"(\d+\.\d+\.\d+[^"]*)"']),
    ("minimatch",            [r'"minimatch"[^}]{0,100}"version":"(\d+\.\d+\.\d+[^"]*)"']),
    ("node-forge",           [r'"node-forge"[^}]{0,100}"version":"(\d+\.\d+\.\d+[^"]*)"']),
]

_RS_FINGERPRINTS = [
    ("react", "Framework UI", [
        "__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED",
        "createElement",
        "createContext",
        "__reactFiber",
    ]),
    ("react-dom", "Framework UI", [
        "__reactFiber",
        "hydrateRoot",
        "createPortal",
        "flushSync",
    ]),
    ("next", "Framework SSR", [
        "__NEXT_DATA__",
        "__next_router_basePath",
        "/_next/static/",
        "NextRouter",
        "__NEXT_CROSS_ORIGIN",
    ]),
    ("axios", "HTTP Client", [
        "isAxiosError",
        "AxiosError",
        "axios.create",
        "CancelToken",
    ]),
    ("lodash", "Utilidades", [
        "_.debounce",
        "_.throttle",
        "_.cloneDeep",
        "_.merge(",
    ]),
    ("moment", "Fechas", [
        "moment.utc",
        "moment.locale",
        "_isAMomentObject",
        "moment.isMoment",
    ]),
    ("date-fns", "Fechas", [
        "dateFns",
        "startOfWeek",
        "endOfMonth",
        "parseISO",
    ]),
    ("framer-motion", "Animaciones", [
        "AnimatePresence",
        "useAnimate",
        "useMotionValue",
        "MotionConfig",
    ]),
    ("@tanstack/react-query", "Data Fetching", [
        "QueryClient",
        "useQuery",
        "useMutation",
        "QueryClientProvider",
    ]),
    ("zustand", "State Manager", [
        "createStore",
        "useStore",
        "subscribeWithSelector",
    ]),
    ("zod", "Validación", [
        "ZodError",
        "z.object",
        "z.string",
        "safeParse",
    ]),
    ("swr", "Data Fetching", [
        "useSWR",
        "SWRConfig",
        "mutate(",
    ]),
    ("next-auth", "Autenticación", [
        "getSession",
        "signIn(",
        "useSession",
        "SessionProvider",
    ]),
    ("@mui/material", "UI Components", [
        "MuiButton",
        "makeStyles",
        "ThemeProvider",
        "createTheme",
    ]),
]


def rs_check_technology(response, html_content: str) -> List[dict]:
    """Detecta firmas de React/Next.js en headers y HTML."""
    results = []
    powered_by = response.headers.get("X-Powered-By", "")
    if "Next.js" in powered_by:
        results.append({"type": "info", "msg": "Tecnología detectada en cabeceras: Next.js"})
    if 'id="__next"' in html_content:
        results.append({"type": "info", "msg": "Estructura DOM de Next.js detectada (div id='__next')."})
    if "data-reactroot" in html_content:
        results.append({"type": "info", "msg": "Atributos de React detectados (data-reactroot)."})
    if "/_next/static/" in html_content:
        results.append({"type": "info", "msg": "Rutas de Next.js detectadas (/_next/static/)."})
    if not results:
        results.append({"type": "low", "msg": "No se detectaron firmas claras de React/Next.js en la página principal."})
    return results


def rs_extract_js_links(base_url: str, html_content: str) -> List[str]:
    """Descubre archivos JS usando 3 estrategias: script tags, manifiestos Next.js, y referencias internas."""
    from urllib.parse import urlparse as _urlparse, urljoin as _urljoin
    parsed = _urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    js_links: set = set()

    soup = BeautifulSoup(html_content, "html.parser")
    for script in soup.find_all("script", src=True):
        src = script['src']
        if src.startswith("/") or origin in src:
            js_links.add(_urljoin(origin, src))

    build_id_match = re.search(r'/_next/static/([a-zA-Z0-9_-]+)/_buildManifest\.js', html_content)
    if not build_id_match:
        build_id_match = re.search(r'/_next/static/([a-zA-Z0-9_-]+)/', html_content)
    if build_id_match:
        build_id = build_id_match.group(1)
        manifest_url = _urljoin(origin, f"/_next/static/{build_id}/_buildManifest.js")
        try:
            res = requests.get(manifest_url, headers=_RS_HEADERS, timeout=_RS_TIMEOUT)
            if res.status_code == 200:
                for path in re.findall(r'"(/_next/static/chunks/[^"]+\.js)"', res.text):
                    js_links.add(_urljoin(origin, path))
        except requests.exceptions.RequestException:
            pass

    nextjs_known_chunks = [
        "/_next/static/chunks/main.js",
        "/_next/static/chunks/webpack.js",
        "/_next/static/chunks/framework.js",
        "/_next/static/chunks/pages/_app.js",
        "/_next/static/chunks/pages/index.js",
    ]
    for chunk in nextjs_known_chunks:
        full_url = _urljoin(origin, chunk)
        try:
            res = requests.head(full_url, headers=_RS_HEADERS, timeout=5)
            if res.status_code == 200:
                js_links.add(full_url)
        except requests.exceptions.RequestException:
            pass

    discovered = list(js_links)[:10]
    for js_url in discovered:
        try:
            res = requests.get(js_url, headers=_RS_HEADERS, timeout=_RS_TIMEOUT)
            if res.status_code == 200:
                for path in re.findall(r'"(/_next/static/[^"]+\.js)"', res.text):
                    js_links.add(_urljoin(origin, path))
                for path in re.findall(r'"(/static/chunks/[^"]+\.js)"', res.text):
                    js_links.add(_urljoin(origin, "/_next" + path))
        except requests.exceptions.RequestException:
            continue

    return list(js_links)[:_RS_MAX_JS_FILES]


def rs_extract_nextjs_info_from_html(html_content: str) -> List[dict]:
    """Lee el bloque __NEXT_DATA__ para obtener la versión de Next.js."""
    libs = []
    match = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.+?)</script>', html_content, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group(1))
            version = (data.get("runtimeConfig", {}) or {}).get("NEXT_PUBLIC_VERSION", "")
            if not version:
                version = data.get("nextVersion", "")
            if version:
                libs.append({"name": "next", "version": version, "ecosystem": "npm", "source": "__NEXT_DATA__ (HTML)"})
        except (json.JSONDecodeError, AttributeError):
            pass
    return libs


def rs_extract_versions_from_cdn_urls(html_content: str) -> List[dict]:
    """Busca versiones incrustadas en URLs de CDN (unpkg, jsdelivr, cdnjs, googleapis)."""
    CDN_PATTERNS = [
        (r'unpkg\.com/([@\w/-]+)@(\d+\.\d+[\.\d]*[^/"\s]*)', lambda m: (m.group(1).lstrip("@"), m.group(2))),
        (r'jsdelivr\.net/npm/([@\w/-]+)@(\d+\.\d+[\.\d]*[^/"\s]*)', lambda m: (m.group(1), m.group(2))),
        (r'cdnjs\.cloudflare\.com/ajax/libs/([\w.\-]+)/([\d.]+)/', lambda m: (m.group(1), m.group(2))),
        (r'ajax\.googleapis\.com/ajax/libs/([\w.\-]+)/([\d.]+)/', lambda m: (m.group(1), m.group(2))),
    ]
    detected: dict = {}
    for pattern, extractor in CDN_PATTERNS:
        for match in re.finditer(pattern, html_content, re.IGNORECASE):
            name, version = extractor(match)
            name = name.rstrip(".js").rstrip(".min")
            if name and version and name not in detected:
                detected[name] = {"name": name, "version": version, "ecosystem": "npm",
                                  "source": f"CDN URL en HTML ({name}@{version})"}
    return list(detected.values())


def rs_extract_version_from_context(content: str, lib_name: str, js_url: str):
    """Busca la versión de una librería escaneando el contexto alrededor de su nombre."""
    VERSION_RE = re.compile(r'(\d+\.\d+\.\d+[a-zA-Z0-9.\-+]*)')
    search_term = f'"{lib_name}"'
    pos = 0
    while True:
        idx = content.find(search_term, pos)
        if idx == -1:
            break
        window = content[max(0, idx - 100): idx + 500]
        versions = VERSION_RE.findall(window)
        for v in versions:
            parts = v.split(".")
            try:
                if all(0 <= int(p) <= 999 for p in parts[:3]):
                    return v
            except ValueError:
                pass
        pos = idx + len(search_term)
    return None


def rs_check_nextjs_version_endpoints(base_url: str, html_content: str) -> List[dict]:
    """Intenta extraer la versión de Next.js desde buildManifest.js y cabeceras HTTP."""
    from urllib.parse import urlparse as _urlparse
    parsed = _urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    libs = []
    build_id_match = re.search(r'"buildId"\s*:\s*"([^"]+)"', html_content)
    if not build_id_match:
        build_id_match = re.search(r'/_next/static/([a-zA-Z0-9_-]{8,})/', html_content)
    if build_id_match:
        build_id = build_id_match.group(1)
        manifest_url = f"{origin}/_next/static/{build_id}/_buildManifest.js"
        try:
            res = requests.get(manifest_url, headers=_RS_HEADERS, timeout=_RS_TIMEOUT)
            if res.status_code == 200:
                v = re.search(r'next[@/\s]v?(\d+\.\d+\.\d+)', res.text, re.IGNORECASE)
                if v:
                    libs.append({"name": "next", "version": v.group(1), "ecosystem": "npm", "source": manifest_url})
        except requests.exceptions.RequestException:
            pass
    for u in [f"{origin}/_next/static/chunks/polyfills.js", f"{origin}/_next/static/chunks/main.js"]:
        try:
            res = requests.head(u, headers=_RS_HEADERS, timeout=5)
            for hdr in [res.headers.get("X-Powered-By", ""), res.headers.get("Server", "")]:
                v = re.search(r'[Nn]ext[./@\s]v?(\d+\.\d+\.\d+)', hdr)
                if v:
                    libs.append({"name": "next", "version": v.group(1), "ecosystem": "npm",
                                 "source": f"HTTP Header ({u})"})
                    break
        except requests.exceptions.RequestException:
            pass
    return libs


def rs_check_osv_vulnerabilities(library_name: str, version: str, ecosystem: str = "npm") -> dict:
    """Consulta la API de OSV.dev para buscar vulnerabilidades conocidas."""
    url = "https://api.osv.dev/v1/query"
    payload = {"version": version, "package": {"name": library_name, "ecosystem": ecosystem}}
    try:
        res = requests.post(url, json=payload, timeout=_RS_TIMEOUT)
        if res.status_code == 200:
            data = res.json()
            if "vulns" in data and len(data["vulns"]) > 0:
                vulns = data["vulns"]
                return {
                    "vulnerable": True,
                    "count": len(vulns),
                    "details": [v.get("id") + " - " + v.get("summary", "Sin resumen") for v in vulns[:5]]
                }
        return {"vulnerable": False}
    except Exception:
        return {"vulnerable": False, "error": True}


def rs_check_libraries_and_vulns(url: str, html_content: str) -> List[dict]:
    """
    Extrae librerías y versiones (S0-S4) y consulta OSV.dev para cada versión.
    Retorna lista de items {"type": ..., "msg": ...} compatible con el template.
    """
    from urllib.parse import urlparse as _urlparse
    detected_libs: dict = {}

    # S0 — __NEXT_DATA__
    for lib in rs_extract_nextjs_info_from_html(html_content):
        detected_libs[lib["name"]] = lib

    # S1 — CDN URLs
    print("[ReactScan] Buscando versiones en URLs de CDN...")
    for lib in rs_extract_versions_from_cdn_urls(html_content):
        if lib["name"] not in detected_libs:
            detected_libs[lib["name"]] = lib

    # S2 — Next.js endpoints
    print("[ReactScan] Consultando endpoints informativos de Next.js...")
    for lib in rs_check_nextjs_version_endpoints(url, html_content):
        if lib["name"] not in detected_libs:
            detected_libs[lib["name"]] = lib

    # S3 — Análisis de archivos JS
    print("[ReactScan] Descubriendo archivos JS...")
    js_links = rs_extract_js_links(url, html_content)
    print(f"[ReactScan] {len(js_links)} archivos JS encontrados. Analizando...")

    js_content_cache: dict = {}
    for i, js_url in enumerate(js_links):
        print(f"    [{i+1}/{len(js_links)}] {js_url[:80]}...", end="\r")
        try:
            res = requests.get(js_url, headers=_RS_HEADERS, timeout=_RS_TIMEOUT)
            if res.status_code == 200:
                js_content_cache[js_url] = res.text
        except requests.exceptions.RequestException:
            pass
    print()

    for js_url, content in js_content_cache.items():
        for lib_name, patterns in _RS_MINIFIED_SIGNATURES:
            for pattern in patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    version = match.group(1).strip().strip('"').strip("'")
                    if re.match(r'^\d+\.\d+', version) and lib_name not in detected_libs:
                        detected_libs[lib_name] = {
                            "name": lib_name, "version": version,
                            "ecosystem": "npm", "source": js_url
                        }
                    break

        for lib_name, category, fingerprints in _RS_FINGERPRINTS:
            if lib_name in detected_libs:
                continue
            hits = sum(1 for fp in fingerprints if fp in content)
            if hits >= 2:
                detected_libs[lib_name] = {
                    "name": lib_name, "version": "desconocida",
                    "category": category, "ecosystem": "npm",
                    "source": js_url, "fingerprint": True
                }

    # S4 — Versión por contexto para libs sin versión
    print("[ReactScan] Intentando determinar versiones por contexto...")
    for name, lib in list(detected_libs.items()):
        if lib.get("fingerprint") and lib["version"] == "desconocida":
            for js_url, content in js_content_cache.items():
                version = rs_extract_version_from_context(content, name, js_url)
                if version:
                    lib["version"] = version
                    lib["source"] = js_url
                    lib["fingerprint"] = False
                    lib["ctx_search"] = True
                    break

    results: List[dict] = []
    js_links_list_html = ""
    if js_links:
        items_html = "".join([f"<li><a href='{u}' target='_blank' style='color:#3498db;'>{u}</a></li>" for u in js_links])
        js_links_list_html = (
            f"<details><summary style='cursor:pointer;color:#4fffb0;'>Ver archivos JS analizados ({len(js_links)})</summary>"
            f"<ul style='font-size:0.8em;'>{items_html}</ul></details>"
        )

    if not detected_libs:
        results.append({"type": "info", "msg": f"No se encontraron versiones de librerías en el código analizado. {js_links_list_html}"})
        return results

    print(f"[ReactScan] {len(detected_libs)} librerías detectadas. Consultando OSV.dev...")
    for name, lib in detected_libs.items():
        version = lib["version"]
        ecosystem = lib["ecosystem"]
        source = lib.get("source", "")
        category = lib.get("category", "")
        is_fp = lib.get("fingerprint", False)
        ctx = lib.get("ctx_search", False)
        source_short = source.split("/")[-1] if "/" in source else source
        source_tag = (f"<br><small style='color:#7d8fa3;'>📂 Encontrado en: "
                      f"<a href='{source}' target='_blank' style='color:#3fa0ff;'>{source_short}</a></small>") if source else ""
        cat_tag = f" <small style='color:#7d8fa3;'>({category})</small>" if category else ""

        if is_fp:
            msg = (f"<b>{name}</b>{cat_tag}{source_tag}"
                   f"<br><span style='color:#ffaa00;'>⚠ Detectada por huella digital — versión no determinada.</span>"
                   f"<br><small>Actualiza a la última versión estable como medida preventiva.</small>")
            results.append({"type": "high", "msg": msg})
        elif ctx:
            msg = (f"<b>{name} ≈ {version}</b>{cat_tag}{source_tag}"
                   f"<br><span style='color:#4fffb0;'>ℹ Versión estimada por contexto — puede ser aproximada.</span>"
                   f"<br><small>Verifica en <a href='https://www.npmjs.com/package/{name}' target='_blank'>npmjs.com/{name}</a></small>")
            results.append({"type": "info", "msg": msg})
        else:
            vuln_info = rs_check_osv_vulnerabilities(name, version, ecosystem)
            if vuln_info.get("vulnerable"):
                details_html = "<ul>" + "".join([
                    "<li><a href='https://osv.dev/vulnerability/{vid}' target='_blank' style='color:#ff4d6d;'>{vd}</a></li>".format(
                        vid=d.split(" - ")[0], vd=d)
                    for d in vuln_info["details"]
                ]) + "</ul>"
                msg = (f"<b>{name} @ {version}</b>{cat_tag}{source_tag}"
                       f"<br><span style='color:#ff4d6d;'>¡Vulnerable! {vuln_info['count']} reporte(s) OSV:</span>{details_html}")
                results.append({"type": "critical", "msg": msg})
            else:
                msg = (f"<b>{name} @ {version}</b>{cat_tag}{source_tag}"
                       f"<br>Sin vulnerabilidades conocidas en OSV.dev.")
                results.append({"type": "success", "msg": msg})

    results.append({"type": "info", "msg": js_links_list_html})
    return results


def rs_check_sensitive_files(url: str) -> List[dict]:
    """Busca archivos de configuración sensibles expuestos públicamente."""
    from urllib.parse import urljoin as _urljoin
    sensitive_paths = ["/.env", "/package.json", "/package-lock.json",
                       "/.next/routes-manifest.json", "/.git/config"]
    results: List[dict] = []
    for path in sensitive_paths:
        target = _urljoin(url, path)
        try:
            res = requests.get(target, headers=_RS_HEADERS, timeout=_RS_TIMEOUT)
            if res.status_code == 200:
                text_preview = res.text[:50].lower()
                if ("{" in res.text or "[core]" in res.text or "password" in res.text or "DB_" in res.text):
                    if "<html" not in text_preview:
                        results.append({"type": "critical",
                                       "msg": f"Archivo sensible expuesto: <a href='{target}' target='_blank' style='color:#ff4d6d;'>{target}</a>"})
        except requests.exceptions.RequestException:
            pass
    return results


def rs_check_source_maps(url: str, html_content: str) -> List[dict]:
    """Detecta source maps (.map) que expondrían código fuente."""
    from urllib.parse import urljoin as _urljoin
    soup = BeautifulSoup(html_content, "html.parser")
    results: List[dict] = []
    for script in soup.find_all("script", src=True):
        src = script['src']
        if src.startswith("/") or url in src:
            target_script = _urljoin(url, src)
            map_url = target_script + ".map"
            try:
                res = requests.get(map_url, headers=_RS_HEADERS, timeout=_RS_TIMEOUT)
                if res.status_code == 200 and "sourcesContent" in res.text:
                    results.append({"type": "high",
                                   "msg": f"Source Map expuesto (código fuente): <a href='{map_url}' target='_blank' style='color:#ffaa00;'>{map_url}</a>"})
            except requests.exceptions.RequestException:
                continue
    return results


def rs_check_nextjs_cves(url: str, html_content: str) -> List[dict]:
    """
    Detección PASIVA de CVEs conocidos en Next.js/React.
    Cubre: CVE-2025-29927, CVE-2025-55182, CVE-2025-55183, CVE-2025-55184.
    """
    from urllib.parse import urlparse as _urlparse
    parsed = _urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    results: List[dict] = []

    is_nextjs = ("/_next/static/" in html_content or "__NEXT_DATA__" in html_content or 'id="__next"' in html_content)
    if not is_nextjs:
        results.append({"type": "info", "msg": "Next.js no detectado → checks de CVE específicos omitidos."})
        return results

    # CVE-2025-29927 — Middleware Auth Bypass
    protected = ["/dashboard", "/admin", "/profile", "/account", "/settings", "/api/admin", "/api/user"]
    bypass_header = {**_RS_HEADERS, "x-middleware-subrequest": "middleware"}
    bypass_found = False
    for route in protected:
        target = origin + route
        try:
            r_normal = requests.get(target, headers=_RS_HEADERS, timeout=_RS_TIMEOUT, allow_redirects=False)
            r_bypass = requests.get(target, headers=bypass_header, timeout=_RS_TIMEOUT, allow_redirects=False)
            nc, bc = r_normal.status_code, r_bypass.status_code
            if nc in (301, 302, 307, 401, 403) and bc == 200:
                results.append({
                    "type": "critical",
                    "msg": (f"<b>CVE-2025-29927 — Middleware Auth Bypass</b> ⚠️ POSIBLEMENTE VULNERABLE<br>"
                            f"Ruta: <code>{route}</code> | Normal: HTTP {nc} → Bypass: HTTP {bc}<br>"
                            f"<small><a href='https://osv.dev/vulnerability/CVE-2025-29927' target='_blank'>CVE-2025-29927</a> "
                            f"· Actualiza Next.js ≥ 12.3.5/13.5.9/14.2.25/15.2.3</small>")
                })
                bypass_found = True
                break
        except requests.exceptions.RequestException:
            continue

    if not bypass_found:
        results.append({
            "type": "success",
            "msg": ("<b>CVE-2025-29927 — Middleware Auth Bypass</b><br>"
                    "No se detectó comportamiento indicativo de bypass en rutas comunes.<br>"
                    f"<small><a href='https://osv.dev/vulnerability/CVE-2025-29927' target='_blank'>CVE-2025-29927</a></small>")
        })

    # CVE-2025-55182 — React2Shell (RSC endpoint)
    rsc_header = {**_RS_HEADERS,
                  "RSC": "1",
                  "Next-Router-State-Tree": "%5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D",
                  "Next-Router-Prefetch": "1"}
    rsc_vulnerable = False
    for route in ["/", "/dashboard", "/about"]:
        target = origin + route
        try:
            res = requests.get(target, headers=rsc_header, timeout=_RS_TIMEOUT)
            ct = res.headers.get("content-type", "")
            if "text/x-component" in ct:
                rsc_vulnerable = True
                results.append({
                    "type": "high",
                    "msg": (f"<b>CVE-2025-55182 — React2Shell (RSC Flight)</b> ⚠️ ENDPOINT RSC EXPUESTO<br>"
                            f"Ruta <code>{route}</code> responde con <code>Content-Type: text/x-component</code>.<br>"
                            f"<small>Versiones seguras: React 19.0.1/19.1.2/19.2.1+ · Next.js 15.0.5/15.2.6+<br>"
                            f"<a href='https://osv.dev/vulnerability/CVE-2025-55182' target='_blank'>CVE-2025-55182</a></small>")
                })
                break
        except requests.exceptions.RequestException:
            continue
    if not rsc_vulnerable:
        results.append({
            "type": "success",
            "msg": ("<b>CVE-2025-55182 — React2Shell</b><br>"
                    "No se detectó endpoint RSC expuesto en rutas comunes.<br>"
                    f"<small><a href='https://osv.dev/vulnerability/CVE-2025-55182' target='_blank'>CVE-2025-55182</a></small>")
        })

    # CVE-2025-55183 — Server Function Source Exposure
    try:
        ah = {**_RS_HEADERS, "Content-Type": "text/plain;charset=UTF-8", "Next-Action": "0" * 40}
        res = requests.post(origin + "/", headers=ah, data="[]", timeout=_RS_TIMEOUT)
        exposed_indicators = ["use server", "import ", "export default", "module.exports"]
        if any(ind in res.text for ind in exposed_indicators) and res.status_code == 200:
            results.append({
                "type": "critical",
                "msg": ("<b>CVE-2025-55183 — Server Function Source Code Exposure</b> ⚠️ POSIBLEMENTE VULNERABLE<br>"
                        "El servidor devolvió código fuente en respuesta a petición de Server Action.<br>"
                        "<small><a href='https://osv.dev/vulnerability/CVE-2025-55183' target='_blank'>CVE-2025-55183</a> · Actualiza Next.js ≥ 15.2.3</small>")
            })
        else:
            results.append({
                "type": "success",
                "msg": ("<b>CVE-2025-55183 — Server Function Source Code Exposure</b><br>"
                        "No se detectó exposición de código fuente en Server Actions.<br>"
                        "<small><a href='https://osv.dev/vulnerability/CVE-2025-55183' target='_blank'>CVE-2025-55183</a></small>")
            })
    except requests.exceptions.RequestException:
        results.append({"type": "low", "msg": "<b>CVE-2025-55183</b> — No se pudo conectar para comprobar Server Actions."})

    # CVE-2025-55184 — App Router DoS
    has_app_router = "/_next/static/chunks/app/" in html_content
    if has_app_router:
        results.append({
            "type": "high",
            "msg": ("<b>CVE-2025-55184 — App Router DoS (Infinite Loop)</b> ⚠️ REQUIERE VERIFICACIÓN<br>"
                    "Se detectó el App Router activo. Si Next.js &lt; 15.2.3, podría ser vulnerable a DoS.<br>"
                    "<small><a href='https://osv.dev/vulnerability/CVE-2025-55184' target='_blank'>CVE-2025-55184</a> · Actualiza Next.js ≥ 15.2.3</small>")
        })
    else:
        results.append({
            "type": "success",
            "msg": ("<b>CVE-2025-55184 — App Router DoS</b><br>"
                    "App Router no detectado — este vector probablemente no aplica.<br>"
                    "<small><a href='https://osv.dev/vulnerability/CVE-2025-55184' target='_blank'>CVE-2025-55184</a></small>")
        })

    return results


def rs_run_active_cve_tests(url: str, html_content: str) -> List[dict]:
    """
    Verificación ACTIVA de CVEs — pruebas confirmatorias más profundas.
    Se ejecuta siempre (sin flag --test) cuando el sitio es Next.js.
    """
    from urllib.parse import urlparse as _urlparse
    parsed = _urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    results: List[dict] = []

    is_nextjs = ("/_next/static/" in html_content or "__NEXT_DATA__" in html_content or 'id="__next"' in html_content)
    if not is_nextjs:
        return results

    print("[ReactScan] Verificación activa de CVEs...")

    # TEST 1 — CVE-2025-29927 confirmatorio (más rutas)
    extended_routes = ["/dashboard", "/admin", "/profile", "/account",
                       "/settings", "/api/admin", "/api/user", "/api/me",
                       "/user", "/panel", "/private", "/secure", "/auth/session"]
    bypass_header = {**_RS_HEADERS, "x-middleware-subrequest": "middleware"}
    test1_result = "not_found"
    for route in extended_routes:
        target = origin + route
        try:
            r_normal = requests.get(target, headers=_RS_HEADERS, timeout=_RS_TIMEOUT, allow_redirects=False)
            r_bypass = requests.get(target, headers=bypass_header, timeout=_RS_TIMEOUT, allow_redirects=False)
            nc, bc = r_normal.status_code, r_bypass.status_code
            if nc in (301, 302, 307, 401, 403) and bc == 200:
                size_diff = abs(len(r_bypass.text) - len(r_normal.text))
                results.append({
                    "type": "critical",
                    "msg": (f"<b>[ACTIVO] CVE-2025-29927 — ✅ BYPASS CONFIRMADO</b><br>"
                            f"Ruta: <code>{route}</code> | Normal: HTTP {nc} | Bypass: HTTP {bc}<br>"
                            f"Diferencia de contenido: {size_diff} bytes<br>"
                            f"<small>Actualiza Next.js ≥ 12.3.5/13.5.9/14.2.25/15.2.3</small>")
                })
                test1_result = "vulnerable"
                break
        except requests.exceptions.RequestException:
            continue
    if test1_result == "not_found":
        results.append({"type": "success",
                        "msg": "<b>[ACTIVO] CVE-2025-29927</b> — Bypass no confirmado en rutas extendidas."})

    # TEST 2 — CVE-2025-55182 (payload RSC benigno)
    rsc_headers = {**_RS_HEADERS,
                   "RSC": "1",
                   "Next-Router-State-Tree": "%5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D",
                   "Next-Router-Prefetch": "0",
                   "Accept": "text/x-component"}
    rsc_confirmed = False
    for route in ["/", "/dashboard", "/about"]:
        try:
            res = requests.get(origin + route, headers=rsc_headers, timeout=_RS_TIMEOUT)
            ct = res.headers.get("content-type", "")
            if "text/x-component" in ct:
                body_preview = res.text[:300]
                vuln_indicators = ["I[", "T[", "S["]
                vuln_score = sum(1 for t in vuln_indicators if t in body_preview)
                is_likely_vuln = vuln_score >= 2
                results.append({
                    "type": "critical" if is_likely_vuln else "high",
                    "msg": (f"<b>[ACTIVO] CVE-2025-55182 — React2Shell — "
                            f"{'ENDPOINT + PROTOCOLO RSC EXPUESTO' if is_likely_vuln else 'ENDPOINT ACTIVO'}</b><br>"
                            f"Ruta: <code>{route}</code> | Content-Type: <code>{ct}</code><br>"
                            f"Tokens RSC detectados: {vuln_score}/3<br>"
                            f"<small>React ≥ 19.0.1/19.1.2/19.2.1 · Next.js ≥ 15.2.6 · "
                            f"<a href='https://osv.dev/vulnerability/CVE-2025-55182' target='_blank'>CVE-2025-55182</a></small>")
                })
                rsc_confirmed = True
                break
        except requests.exceptions.RequestException:
            continue
    if not rsc_confirmed:
        results.append({"type": "success",
                        "msg": "<b>[ACTIVO] CVE-2025-55182</b> — Endpoint RSC no respondió con <code>text/x-component</code>."})

    # TEST 3 — CVE-2025-55183 (múltiples action IDs)
    action_ids = ["a" * 40, "0" * 40, "1" * 40, "deadbeef" + "a" * 32]
    code_exposure_found = False
    for action_id in action_ids:
        try:
            ah = {**_RS_HEADERS, "Content-Type": "text/plain;charset=UTF-8", "Next-Action": action_id}
            res = requests.post(origin + "/", headers=ah, data="[]", timeout=_RS_TIMEOUT)
            code_keywords = ['"use server"', "use server", "module.exports", "export default", "import React", "import {"]
            found = [kw for kw in code_keywords if kw in res.text]
            if found and res.status_code == 200:
                results.append({
                    "type": "critical",
                    "msg": (f"<b>[ACTIVO] CVE-2025-55183 — ✅ CÓDIGO FUENTE EXPUESTO</b><br>"
                            f"Action ID: <code>{action_id[:12]}...</code><br>"
                            f"Palabras clave: <code>{', '.join(found)}</code><br>"
                            f"<small><a href='https://osv.dev/vulnerability/CVE-2025-55183' target='_blank'>CVE-2025-55183</a> · Actualiza Next.js ≥ 15.2.3</small>")
                })
                code_exposure_found = True
                break
        except requests.exceptions.RequestException:
            continue
    if not code_exposure_found:
        results.append({"type": "success",
                        "msg": "<b>[ACTIVO] CVE-2025-55183</b> — Sin exposición de código fuente en Server Actions probadas."})

    return results


# =============================
# Scanner
# =============================
class DarkmLens:
    """
    DarkmLens v4.5 (Darkmoon)
    - Defensive passive analysis (authorized only).
    - v4.3: Threading / parallel fetch, deep-endpoints.
    - v4.4: Directory fuzzing, directory listing detection, Google dorks, Firebase probing.
    - v4.5 NEW:
      * Smart spider: sitemap.xml / robots.txt / Next.js route-manifest seeding
      * SPA router extraction (React Router, Vue Router, Angular Router)
      * API call confidence scoring (0-100) on every inferred request
      * TanStack Query / SWR / RTK Query endpoint extraction
      * GraphQL operation name extraction (gql`...` templates)
      * BASE_URL + relative path combination for cross-file endpoint inference
      * Improved dedup: groups by (method, url), keeps highest-confidence finding
      * Frontend map tree in results JSON
      * --no-sitemap, --min-confidence CLI flags
      * max-pages default 40, max-depth default 4
    """

    VERSION = "4.5"

    ABS_URL_RE = re.compile(r'https?://[^\s"\'<>]+(?:\?[^\s"\'<>]+)?', re.IGNORECASE)

    # endpoints-ish relative
    REL_ENDPOINT_RE = re.compile(r'["\'](\/(?:api|graphql|gql|auth|oauth|v\d+|rest|services)\/[^"\']+)["\']', re.IGNORECASE)
    GRAPHQL_HINT_RE = re.compile(r'\/graphql\b|\/gql\b', re.IGNORECASE)
    WS_RE = re.compile(r'\b(wss?:\/\/[^\s"\'<>]+)', re.IGNORECASE)

    ROUTE_RE = re.compile(r'["\'](\/[^"\']{1,220})["\']')
    ASSET_EXT_RE = re.compile(r".*\.(png|jpg|jpeg|gif|webp|svg|ico|css|js|map|woff2?|ttf|eot)(\?.*)?$", re.IGNORECASE)
    SOURCEMAP_RE = re.compile(r"sourceMappingURL\s*=\s*([^\s]+)")
    BASEURL_RE = re.compile(r'(baseURL|BASE_URL|API_URL|NEXT_PUBLIC_API_URL|VITE_API_URL|REACT_APP_API_URL)\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE)

    # common trackers/configs
    SENTRY_RE = re.compile(r'https:\/\/[a-z0-9]+@o\d+\.ingest\.sentry\.io\/\d+', re.IGNORECASE)
    GA_RE = re.compile(r'\bG-[A-Z0-9]{8,}\b|\bUA-\d{4,}-\d+\b', re.IGNORECASE)
    SEGMENT_RE = re.compile(r'analytics\.load\(["\']([a-z0-9]{10,})["\']\)', re.IGNORECASE)

    # AWS
    COGNITO_RE = re.compile(r'\b(userPoolId|userPoolWebClientId|identityPoolId|aws_project_region|cognito-idp\.[a-z0-9-]+\.amazonaws\.com)\b', re.IGNORECASE)
    APPSYNC_RE = re.compile(r'\b(appSyncGraphqlEndpoint|aws_appsync_graphqlEndpoint|aws_appsync_authenticationType|AWSAppSync)\b', re.IGNORECASE)

    # Firebase
    FIREBASE_HINT_RE = re.compile(r'firebaseapp\.com|firebaseio\.com|gstatic\.com/firebasejs|firebase', re.IGNORECASE)
    # Firebase config: find any block containing apiKey (AIzaSy...) near other Firebase fields.
    # Flexible: any order, allows nested braces, backticks, minified code.
    FIREBASE_STRICT_RE = re.compile(
        r'(?:firebaseConfig|initializeApp|getApp|getApps)'
        r'\s*[=(,]\s*'
        r'(\{[^;]{0,3000}?apiKey\s*[:=]\s*["`\'][^"`\']{10,}["`\'][^;]{0,3000}?\})',
        re.IGNORECASE | re.DOTALL
    )
    # Fallback: any object with apiKey that looks like a Firebase API key (AIzaSy...)
    FIREBASE_APIKEY_RE = re.compile(
        r'(\{[^;]{0,500}?apiKey\s*[:=]\s*["`\'](AIzaSy[A-Za-z0-9_\-]{30,})["`\'][^;]{0,2000}?\})',
        re.IGNORECASE | re.DOTALL
    )
    FIRESTORE_REST_RE = re.compile(r'https:\/\/firestore\.googleapis\.com\/v1\/projects\/[^"\']+?\/databases\/\([^"\']+?\)\/documents\/[^"\']+', re.IGNORECASE)
    FIRESTORE_DOCS_PATH_RE = re.compile(r'\/documents\/([^?\s"\'<>#]+)', re.IGNORECASE)
    RTDB_RE = re.compile(r'https:\/\/([a-z0-9-]+)\.firebaseio\.com\/([^"\']+?)\.json', re.IGNORECASE)
    FIRESTORE_COLLECTION_CALL_RE = re.compile(r'\bcollection\s*\(\s*["\']([a-zA-Z0-9_-]{1,80})["\']\s*\)', re.IGNORECASE)
    FIRESTORE_COLLECTIONGROUP_CALL_RE = re.compile(r'\bcollectionGroup\s*\(\s*["\']([a-zA-Z0-9_-]{1,80})["\']\s*\)', re.IGNORECASE)

    # ── v4.5: SPA Router route extraction ─────────────────────────────────
    # React Router: <Route path="/dashboard" /> or { path: "/dashboard", element: ... }
    REACT_ROUTER_JSX_RE = re.compile(r'path\s*[:=]\s*["\'](\/[^"\'\s\(\)\\]{1,200})["\']', re.IGNORECASE)
    # Vue Router: { path: '/about', component: ... }
    VUE_ROUTER_PATH_RE = re.compile(r'(?:^|,|\{)\s*path\s*:\s*["\'](\/[^"\'\s\\]{0,200})["\']', re.IGNORECASE | re.MULTILINE)
    # Angular Router: { path: 'dashboard', component: ... } (relative paths)
    ANGULAR_ROUTER_PATH_RE = re.compile(r'path\s*:\s*["\']([a-zA-Z0-9:_/-]{1,120})["\']\s*,\s*(?:component|loadChildren|redirectTo)', re.IGNORECASE)
    # Generic SPA route object: { "/route": Component } or routes map
    SPA_ROUTE_OBJECT_RE = re.compile(r'["\'](\/[a-zA-Z0-9/_:-]{1,120})["\']\s*:\s*(?:[a-zA-Z_$][a-zA-Z0-9_$]*|lazy\(|import\()', re.IGNORECASE)

    # ── v4.5: TanStack / React Query / RTK Query ──────────────────────────
    # useQuery / useMutation / useInfiniteQuery with URL key
    TANSTACK_QUERY_URL_RE = re.compile(
        r'(?:useQuery|useMutation|useInfiniteQuery|useSuspenseQuery)\s*\(\s*(?:\{[^}]{0,400}(?:queryKey|mutationKey)\s*:\s*\[[^\]]{0,200}\]|[^)]{0,300})\s*(?:queryFn|mutationFn)\s*:\s*[^,}]{0,300}fetch\s*\(\s*["\`]([^"\'\`]+)["\`]',
        re.IGNORECASE | re.DOTALL
    )
    # queryFn arrow with explicit URL
    TANSTACK_QUERYFN_RE = re.compile(
        r'queryFn\s*:\s*(?:async\s*)?(?:\(\)\s*=>|function\s*\(\)\s*)\s*(?:await\s*)?(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["\`]([^"\'\`]+)["\`]',
        re.IGNORECASE | re.DOTALL
    )
    # RTK Query: createApi baseQuery baseUrl
    RTK_BASE_URL_RE = re.compile(r'fetchBaseQuery\s*\(\s*\{[^}]{0,200}baseUrl\s*:\s*["\`\']([^"\'\`]+)["\`\']', re.IGNORECASE | re.DOTALL)
    # RTK builder.query / builder.mutation with url
    RTK_ENDPOINT_RE = re.compile(r'builder\.(?:query|mutation)\s*\(\s*\{[^}]{0,400}(?:url|query)\s*:\s*(?:["\`\']([^"\'\`]+)["\`\']|\([^)]{0,80}\)\s*=>\s*[^,\n}{]{0,80}["\`\']([^"\'\`]+)["\`\'])', re.IGNORECASE | re.DOTALL)
    # SWR: useSWR('/api/...', fetcher)
    SWR_RE = re.compile(r'useSWR\s*\(\s*["\`\']([^"\'\`]+)["\`\']', re.IGNORECASE)

    # ── v4.5: GraphQL ─────────────────────────────────────────────────────
    # gql`query OpName { ... }` or gql`mutation OpName { ... }`
    GQL_OPERATION_RE = re.compile(
        r'(?:gql\s*|graphql\s*|gql\s*`|graphql\s*`)\s*[`"]\s*(query|mutation|subscription)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\([^)]{0,400}\))?\s*\{',
        re.IGNORECASE
    )
    # Inline GraphQL via string query: { query: "query { ... }" }
    GQL_INLINE_RE = re.compile(r'["\']query["\']\s*:\s*["\']\s*(query|mutation)\s+([a-zA-Z_][a-zA-Z0-9_]*)', re.IGNORECASE)

    # bad route filters
    BAD_ROUTE_CHARS_RE = re.compile(r'[<>"\'{}\(\)\*\$,]|\\n|\\r|\\t')
    BAD_ROUTE_PATTERNS_RE = re.compile(r'\/\(\.\+\?\)|\(\.\+\?\)|\[\^\/\]\+\?\)|\(\[\^\/\]\+\?\)|\/\.\*|\/\.\+|\(\?:|\|\|', re.IGNORECASE)

    # Request inference (fetch/axios)
    FETCH_CALL_RE = re.compile(
        r'\bfetch\s*\(\s*(?P<q>["\'])(?P<url>[^"\']+)(?P=q)\s*(?:,\s*(?P<opts>\{.*?\}))?\s*\)',
        re.IGNORECASE | re.DOTALL
    )
    FETCH_METHOD_RE = re.compile(r'\bmethod\s*:\s*(?P<q>["\'])(?P<m>[A-Z]+)(?P=q)', re.IGNORECASE)
    FETCH_HEADERS_RE = re.compile(r'\bheaders\s*:\s*(?P<h>\{.*?\})', re.IGNORECASE | re.DOTALL)
    FETCH_BODY_RE = re.compile(r'\bbody\s*:\s*(?P<b>[^,}\n]+)', re.IGNORECASE)

    AXIOS_SHORT_RE = re.compile(
        r'\baxios\.(get|post|put|patch|delete)\s*\(\s*(?P<q>["\'])(?P<url>[^"\']+)(?P=q)',
        re.IGNORECASE
    )
    AXIOS_OBJ_RE = re.compile(r'\baxios\s*\(\s*(?P<obj>\{.*?\})\s*\)', re.IGNORECASE | re.DOTALL)
    AXIOS_URL_IN_OBJ_RE = re.compile(r'\burl\s*:\s*(?P<q>["\'])(?P<url>[^"\']+)(?P=q)', re.IGNORECASE)
    AXIOS_METHOD_IN_OBJ_RE = re.compile(r'\bmethod\s*:\s*(?P<q>["\'])(?P<m>[a-z]+)(?P=q)', re.IGNORECASE)
    AXIOS_PARAMS_IN_OBJ_RE = re.compile(r'\bparams\s*:\s*\{(?P<p>.*?)\}', re.IGNORECASE | re.DOTALL)
    AXIOS_DATA_IN_OBJ_RE = re.compile(r'\bdata\s*:\s*(?P<d>\{.*?\}|\[.*?\]|["\'][^"\']*["\']|`[^`]*`)', re.IGNORECASE | re.DOTALL)
    AXIOS_HEADERS_IN_OBJ_RE = re.compile(r'\bheaders\s*:\s*(?P<h>\{.*?\})', re.IGNORECASE | re.DOTALL)

    # URLSearchParams params extraction
    URLSEARCHPARAMS_OBJ_RE = re.compile(r'new\s+URLSearchParams\s*\(\s*\{(?P<obj>.*?)\}\s*\)', re.IGNORECASE | re.DOTALL)

    # JS navigation discovery
    JS_NAV_RE = [
        re.compile(r'(?:window\.)?location\.href\s*=\s*(?P<q>["\'])(?P<u>[^"\']+)(?P=q)', re.IGNORECASE),
        re.compile(r'(?:window\.)?location\.(?:assign|replace)\s*\(\s*(?P<q>["\'])(?P<u>[^"\']+)(?P=q)\s*\)', re.IGNORECASE),
        re.compile(r'history\.pushState\s*\(\s*.*?,\s*.*?,\s*(?P<q>["\'])(?P<u>[^"\']+)(?P=q)\s*\)', re.IGNORECASE),
        re.compile(r'history\.replaceState\s*\(\s*.*?,\s*.*?,\s*(?P<q>["\'])(?P<u>[^"\']+)(?P=q)\s*\)', re.IGNORECASE),
        re.compile(r'router\.navigate(?:ByUrl)?\s*\(\s*(?P<arg>\[.*?\]|(?P<q>["\'])(?P<u>[^"\']+)(?P=q))', re.IGNORECASE | re.DOTALL),
        re.compile(r'\bnavigate\s*\(\s*(?P<q>["\'])(?P<u>\/[^"\']+)(?P=q)', re.IGNORECASE),
        re.compile(r'router\.(?:push|replace)\s*\(\s*(?P<q>["\'])(?P<u>\/[^"\']+)(?P=q)', re.IGNORECASE),
        re.compile(r'window\.open\s*\(\s*(?P<q>["\'])(?P<u>[^"\']+)(?P=q)', re.IGNORECASE),
    ]

    # naive framework hints
    ANGULAR_HINT_RE = re.compile(r'\bng-version\b|@angular\/|angular\.min\.js|Zone\.js', re.IGNORECASE)
    VUE_HINT_RE = re.compile(r'\bVue\b|vue-router|__VUE__|data-v-', re.IGNORECASE)
    SVELTE_HINT_RE = re.compile(r'\bsvelte\b|__SVELTE__', re.IGNORECASE)
    NUxT_HINT_RE = re.compile(r'__NUXT__|nuxt', re.IGNORECASE)
    REMIX_HINT_RE = re.compile(r'__remixContext|@remix-run|remix\.run', re.IGNORECASE)
    GATSBY_HINT_RE = re.compile(r'___gatsby|gatsby-chunk|gatsby-browser', re.IGNORECASE)
    ASTRO_HINT_RE = re.compile(r'astro:page-load|astro-island|@astrojs', re.IGNORECASE)

    # ── Python / backend frameworks ───────────────────────────────────────
    DJANGO_HINTS_RE = re.compile(r'csrfmiddlewaretoken|django|DJANGO_SETTINGS|python-requests', re.IGNORECASE)
    FLASK_HINTS_RE = re.compile(r'\bFlask\b|Werkzeug|flask_login|flask_wtf', re.IGNORECASE)
    FASTAPI_HINTS_RE = re.compile(r'\bFastAPI\b|uvicorn|starlette|/openapi\.json\b', re.IGNORECASE)
    LARAVEL_HINTS_RE = re.compile(r'\blaravel\b|illuminate|XSRF-TOKEN|laravel_session', re.IGNORECASE)
    RAILS_HINTS_RE = re.compile(r'\bRails\b|ActionController|Turbolinks|rails-ujs', re.IGNORECASE)
    SPRING_HINTS_RE = re.compile(r'Spring|Tomcat|/actuator/|org\.springframework', re.IGNORECASE)
    DOTNET_HINTS_RE = re.compile(r'\bBlazor\b|aspnet|\.aspx\b|asp\.net', re.IGNORECASE)
    WORDPRESS_HINTS_RE = re.compile(r'wp-content|wp-includes|wp-json|WordPress', re.IGNORECASE)
    SHOPIFY_HINTS_RE = re.compile(r'Shopify\.theme|shopify\.com|cdn\.shopify\.com', re.IGNORECASE)

    # ── Supabase ──────────────────────────────────────────────────────────
    SUPABASE_URL_RE = re.compile(r'https?://[a-z0-9]+\.supabase\.(?:co|com)', re.IGNORECASE)
    SUPABASE_KEY_RE = re.compile(r'supabaseUrl|supabaseKey|SUPABASE_URL|SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE', re.IGNORECASE)
    SUPABASE_TABLE_RE = re.compile(r'\.from\s*\(\s*["\']([a-zA-Z0-9_-]{1,80})["\']\s*\)', re.IGNORECASE)

    # ── Auth0 ─────────────────────────────────────────────────────────────
    AUTH0_DOMAIN_RE = re.compile(r'([a-zA-Z0-9-]+\.(?:us\d+\.|eu\.|au\.)?auth0\.com)', re.IGNORECASE)
    AUTH0_HINT_RE = re.compile(r'auth0|Auth0Provider|useAuth0|createAuth0Client|@auth0/', re.IGNORECASE)

    # ── Clerk ─────────────────────────────────────────────────────────────
    CLERK_HINT_RE = re.compile(r'clerk\.dev|clerk\.com|@clerk/|ClerkProvider|useClerk', re.IGNORECASE)

    # ── Stripe ────────────────────────────────────────────────────────────
    STRIPE_HINT_RE = re.compile(r'stripe\.com|js\.stripe\.com|\bStripe\s*\(', re.IGNORECASE)
    STRIPE_KEY_RE = re.compile(r'\b(pk_(?:live|test)_[a-zA-Z0-9]{24,})', re.IGNORECASE)

    # ── Other third-party services ────────────────────────────────────────
    MIXPANEL_RE = re.compile(r'mixpanel\.track|api\.mixpanel\.com|mixpanel\.init|mixpanel\.identify', re.IGNORECASE)
    INTERCOM_RE = re.compile(r'intercomSettings|intercom\.io|widget\.intercom\.io|Intercom\(', re.IGNORECASE)
    PUSHER_RE = re.compile(r'pusher\.com|new\s+Pusher\s*\(|pusher-js|pusherKey', re.IGNORECASE)
    ALGOLIA_RE = re.compile(r'algolia\.net|algoliasearch\s*\(|\.algolia\.com', re.IGNORECASE)
    GMAPS_RE = re.compile(r'maps\.googleapis\.com|google\.maps\.|initMap\s*\(|@googlemaps/', re.IGNORECASE)
    MAPBOX_HINT_RE = re.compile(r'mapbox\.com|mapboxgl\.Map|mapboxgl\.accessToken|@mapbox/', re.IGNORECASE)
    MAPBOX_TOKEN_RE = re.compile(r'\b(pk\.[a-zA-Z0-9._-]{60,})', re.IGNORECASE)
    TWILIO_RE = re.compile(r'twilio\.com|@twilio/|TwilioVideo|twilio-video', re.IGNORECASE)
    ONESIGNAL_RE = re.compile(r'onesignal\.com|OneSignal\.init|OneSignalSDK', re.IGNORECASE)
    RECAPTCHA_RE = re.compile(r'recaptcha\.net|google\.com/recaptcha|grecaptcha\.execute|hcaptcha\.com', re.IGNORECASE)
    HOTJAR_RE = re.compile(r'hotjar\.com|hjSiteSettings|_hjSettings', re.IGNORECASE)
    DATADOG_RE = re.compile(r'datadoghq\.com|DD_RUM|datadogRum\.init', re.IGNORECASE)
    LAUNCHDARKLY_RE = re.compile(r'launchdarkly\.com|LDClient|@launchdarkly/', re.IGNORECASE)
    AMPLITUDE_RE = re.compile(r'amplitude\.com|amplitude\.getInstance|@amplitude/', re.IGNORECASE)
    POSTHOG_RE = re.compile(r'posthog\.com|posthog\.init|posthog\.capture', re.IGNORECASE)

    # ── Route type classifier ─────────────────────────────────────────────
    BACKEND_PATH_RE = re.compile(
        r'^\/(?:api|graphql|gql|rest|services|v\d+[\/]|auth|oauth|token|webhook|webhooks|ws|socket\.io|rpc|trpc|swagger|openapi|actuator|admin\/api|_next\/data)',
        re.IGNORECASE
    )
    # ── Directory Listing detection ───────────────────────────────────────
    DIRLIST_INDICATORS = [
        re.compile(r'<title>\s*Index\s+of\s+/', re.IGNORECASE),
        re.compile(r'<h1>\s*Index\s+of\s+/', re.IGNORECASE),
        re.compile(r'Directory\s+listing\s+for\b', re.IGNORECASE),
        re.compile(r'<pre>.*<a\s+href="[^"]*/">', re.IGNORECASE | re.DOTALL),
        re.compile(r'autoindex\s+on', re.IGNORECASE),
        re.compile(r'<address>.*Apache/.*Server\s+at', re.IGNORECASE | re.DOTALL),
        re.compile(r'<address>.*nginx', re.IGNORECASE),
        re.compile(r'\[To Parent Directory\]', re.IGNORECASE),
        re.compile(r'<title>.*Directory\s+Listing.*</title>', re.IGNORECASE),
    ]

    # ── Built-in fuzz wordlist (~200 common paths) ────────────────────────
    DEFAULT_FUZZ_PATHS = [
        # Admin panels
        "/admin", "/admin/", "/administrator", "/admin/login", "/admin/dashboard",
        "/panel", "/cpanel", "/wp-admin", "/wp-login.php", "/manager", "/manage",
        "/dashboard", "/portal", "/controlpanel", "/admin-console", "/adminer",
        "/phpmyadmin", "/pma", "/sql", "/mysql", "/myadmin",
        # Login / Auth
        "/login", "/signin", "/signup", "/register", "/auth", "/auth/login",
        "/oauth", "/sso", "/cas/login", "/accounts/login", "/user/login",
        # API & docs
        "/api", "/api/v1", "/api/v2", "/api/v3", "/api/docs", "/api/swagger",
        "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger.json", "/swagger.yaml",
        "/openapi.json", "/openapi.yaml", "/api-docs", "/redoc", "/graphql",
        "/graphiql", "/playground", "/api/graphql", "/graphql/console",
        # Config / sensitive files
        "/.env", "/.env.local", "/.env.production", "/.env.development",
        "/.env.bak", "/.env.old", "/.env.example",
        "/.git", "/.git/config", "/.git/HEAD", "/.gitignore",
        "/.svn", "/.svn/entries", "/.hg",
        "/.htaccess", "/.htpasswd", "/web.config", "/crossdomain.xml",
        "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
        "/security.txt", "/.well-known/security.txt",
        "/humans.txt", "/ads.txt",
        # Backups
        "/backup", "/backups", "/bak", "/dump", "/dump.sql",
        "/database.sql", "/db.sql", "/data.sql", "/backup.sql",
        "/backup.zip", "/backup.tar.gz", "/backup.rar",
        "/site.zip", "/site.tar.gz", "/www.zip",
        "/old", "/archive", "/temp", "/tmp",
        # WordPress
        "/wp-content", "/wp-includes", "/wp-json", "/wp-json/wp/v2/users",
        "/xmlrpc.php", "/wp-config.php", "/wp-config.php.bak",
        "/wp-cron.php", "/readme.html", "/license.txt",
        # Common frameworks
        "/server-status", "/server-info",
        "/actuator", "/actuator/health", "/actuator/env", "/actuator/info",
        "/elmah.axd", "/trace.axd",
        "/_debug", "/debug", "/debug/default/view",
        "/info.php", "/phpinfo.php", "/test.php", "/info",
        "/console", "/rails/info/routes",
        "/__debug__", "/silk/",
        "/docs", "/redoc",
        # Firebase / cloud
        "/__/firebase/init.js", "/__/firebase/init.json",
        "/__/auth/handler", "/__/auth/iframe",
        "/firebase-messaging-sw.js", "/manifest.json",
        "/_ah/health", "/healthz", "/health", "/healthcheck", "/status", "/ping",
        # CI/CD & DevOps
        "/.github", "/.gitlab-ci.yml", "/.circleci/config.yml",
        "/Jenkinsfile", "/Dockerfile", "/docker-compose.yml",
        "/.dockerignore", "/Procfile", "/Makefile",
        "/.travis.yml", "/.drone.yml",
        # Package / dependency files
        "/package.json", "/package-lock.json", "/yarn.lock",
        "/composer.json", "/composer.lock", "/Gemfile", "/Gemfile.lock",
        "/requirements.txt", "/Pipfile", "/Pipfile.lock",
        "/pom.xml", "/build.gradle",
        # Misc sensitive
        "/config", "/config.json", "/config.yml", "/config.yaml",
        "/settings.json", "/settings.yml",
        "/.DS_Store", "/Thumbs.db",
        "/error", "/errors", "/error_log", "/error.log",
        "/access.log", "/debug.log",
        "/uploads", "/upload", "/files", "/media", "/assets",
        "/static", "/public", "/private", "/internal",
        "/cgi-bin", "/cgi-bin/",
        "/vendor", "/node_modules", "/bower_components",
        # CMS & ecommerce
        "/cms", "/joomla", "/drupal", "/magento",
        "/shop", "/store", "/cart", "/checkout",
        # Webmail & tools
        "/webmail", "/mail", "/roundcube", "/squirrelmail",
        "/owa", "/autodiscover/autodiscover.xml",
        # Storage / data
        "/data", "/db", "/database", "/storage", "/var",
        "/logs", "/log",
        # Testing / staging
        "/test", "/testing", "/staging", "/dev", "/development",
        "/beta", "/alpha", "/sandbox", "/demo",
        # SSO / identity
        "/saml", "/saml/metadata", "/.well-known/openid-configuration",
        "/oauth/authorize", "/oauth/token",
    ]

    # ── Google Dork templates ─────────────────────────────────────────────
    GOOGLE_DORK_TEMPLATES = [
        {"cat": "Admin Panels", "tpl": 'site:{domain} inurl:admin', "desc": "Páginas de administración"},
        {"cat": "Admin Panels", "tpl": 'site:{domain} inurl:login', "desc": "Páginas de login"},
        {"cat": "Admin Panels", "tpl": 'site:{domain} inurl:dashboard', "desc": "Dashboards expuestos"},
        {"cat": "Admin Panels", "tpl": 'site:{domain} intitle:"panel" inurl:admin', "desc": "Panel de administración"},
        {"cat": "Archivos Sensibles", "tpl": 'site:{domain} ext:sql', "desc": "Archivos SQL expuestos"},
        {"cat": "Archivos Sensibles", "tpl": 'site:{domain} ext:env', "desc": "Archivos .env expuestos"},
        {"cat": "Archivos Sensibles", "tpl": 'site:{domain} ext:log', "desc": "Archivos de log"},
        {"cat": "Archivos Sensibles", "tpl": 'site:{domain} ext:bak', "desc": "Archivos de backup"},
        {"cat": "Archivos Sensibles", "tpl": 'site:{domain} ext:conf OR ext:cfg', "desc": "Archivos de configuración"},
        {"cat": "Archivos Sensibles", "tpl": 'site:{domain} ext:xml inurl:config', "desc": "Configs XML"},
        {"cat": "Archivos Sensibles", "tpl": 'site:{domain} ext:json inurl:config', "desc": "Configs JSON"},
        {"cat": "Archivos Sensibles", "tpl": 'site:{domain} ext:yml OR ext:yaml', "desc": "Archivos YAML"},
        {"cat": "Directory Listing", "tpl": 'site:{domain} intitle:"index of"', "desc": "Directorios abiertos"},
        {"cat": "Directory Listing", "tpl": 'site:{domain} intitle:"directory listing"', "desc": "Listado de directorios"},
        {"cat": "Backups", "tpl": 'site:{domain} ext:zip OR ext:rar OR ext:tar.gz', "desc": "Archivos comprimidos"},
        {"cat": "Backups", "tpl": 'site:{domain} ext:sql "INSERT INTO" OR "CREATE TABLE"', "desc": "Dumps de base de datos"},
        {"cat": "Backups", "tpl": 'site:{domain} inurl:backup', "desc": "Rutas de backup"},
        {"cat": "Firebase / Cloud", "tpl": 'site:{domain} inurl:firebaseio', "desc": "Firebase RTDB expuesto"},
        {"cat": "Firebase / Cloud", "tpl": 'site:{domain} inurl:__/firebase', "desc": "Firebase hosting config"},
        {"cat": "Firebase / Cloud", "tpl": 'site:firebasestorage.googleapis.com "{domain}"', "desc": "Firebase Storage público"},
        {"cat": "Firebase / Cloud", "tpl": 'site:{domain} inurl:.firebaseapp.com', "desc": "Firebase App URL"},
        {"cat": "Backend / API", "tpl": 'site:{domain} inurl:api', "desc": "Endpoints de API"},
        {"cat": "Backend / API", "tpl": 'site:{domain} inurl:graphql', "desc": "Endpoints GraphQL"},
        {"cat": "Backend / API", "tpl": 'site:{domain} inurl:swagger OR inurl:api-docs', "desc": "Documentación API"},
        {"cat": "Backend / API", "tpl": 'site:{domain} ext:json inurl:openapi', "desc": "OpenAPI spec"},
        {"cat": "Info Disclosure", "tpl": 'site:{domain} intitle:"phpinfo()"', "desc": "phpinfo() expuesto"},
        {"cat": "Info Disclosure", "tpl": 'site:{domain} intext:"password" ext:log', "desc": "Passwords en logs"},
        {"cat": "Info Disclosure", "tpl": 'site:{domain} intext:"DB_PASSWORD" OR intext:"DB_HOST"', "desc": "Credenciales de DB"},
        {"cat": "Info Disclosure", "tpl": 'site:{domain} inurl:.git', "desc": "Repositorio Git expuesto"},
        {"cat": "Info Disclosure", "tpl": 'site:{domain} inurl:wp-config', "desc": "WordPress config expuesto"},
        {"cat": "Errores Expuestos", "tpl": 'site:{domain} intext:"SQL syntax" OR intext:"mysql_fetch"', "desc": "Errores SQL"},
        {"cat": "Errores Expuestos", "tpl": 'site:{domain} intext:"Warning:" intext:"on line"', "desc": "PHP warnings"},
        {"cat": "Errores Expuestos", "tpl": 'site:{domain} intext:"stack trace" OR intext:"traceback"', "desc": "Stack traces"},
    ]

    def __init__(
        self,
        target_url: str,
        out_dir: str = "out",
        max_assets: int = 120,
        max_map_files: int = 20,
        request_timeout: int = 15,
        sleep_between: float = 0.03,
        screenshot: bool = True,
        crawl_pages: bool = True,
        max_pages: int = 25,
        max_depth: int = 2,
        extra_headers: Optional[Dict[str, str]] = None,
        save_route_bodies: bool = True,
        probe_get_endpoints: bool = False,

        # AuthZ audit
        audit_authz: bool = False,
        authz_max_routes: int = 200,
        authz_take_screenshots: bool = True,
        authz_show_response: bool = False,
        authz_response_chars: int = 900,

        # Optional AI summary (Ollama / Claude)
        ai_ollama: bool = False,
        ai_js_extract: bool = False,
        ai_model: str = "dolphin-llama3:latest",
        ai_api_key: str = "",

        # NEW
        deep_endpoints: bool = False,

        # v4.4: Fuzzing
        fuzz: bool = False,
        fuzz_wordlist_file: Optional[str] = None,
        fuzz_max: int = 500,
        fuzz_threads: Optional[int] = None,

        # v4.4: Google dorks (passive)
        google_dorks: bool = True,

        # v4.4: Firebase probing (active)
        probe_firebase: bool = False,

        # v4.5: Sitemap/robots probe + confidence filtering
        probe_sitemap: bool = True,
        min_confidence: int = 0,

        # THREADS
        threads: int = 12,
        asset_threads: Optional[int] = None,
        crawl_threads: Optional[int] = None,
        authz_threads: Optional[int] = None,
        deep_threads: Optional[int] = None,
        **kwargs
    ):
        self.target_url = target_url
        self.out_dir = out_dir
        self.max_assets = max_assets
        self.max_map_files = max_map_files
        self.request_timeout = request_timeout
        self.sleep_between = sleep_between
        self.enable_screenshot = screenshot
        self.crawl_pages = crawl_pages
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.extra_headers = extra_headers or {}
        self.save_route_bodies = save_route_bodies
        self.probe_get_endpoints = probe_get_endpoints

        self.audit_authz = audit_authz
        self.authz_max_routes = authz_max_routes
        self.authz_take_screenshots = authz_take_screenshots
        self.authz_show_response = authz_show_response
        self.authz_response_chars = authz_response_chars

        self.ai_ollama = ai_ollama
        self.ai_provider = kwargs.get("ai_provider", "claude")
        self.ai_js_extract = ai_js_extract
        self.ai_model = ai_model
        self.ai_api_key = ai_api_key
        self.lm_studio_url = kwargs.get("lm_studio_url", "")
        self.ollama_url = kwargs.get("ollama_url", "http://localhost:11434")
        self.claude_code_extra_prompt = kwargs.get("claude_code_extra_prompt", "")
        self.claude_code_prompt_file = kwargs.get("claude_code_prompt_file", "")
        self.claude_code_bin = kwargs.get("claude_code_bin", "claude")
        self.claude_code_timeout = int(kwargs.get("claude_code_timeout", 180) or 180)

        self._ai_lock = threading.Lock()
        self._ai_js_urls_lock = threading.Lock()
        self._ai_saved_js_lock = threading.Lock()
        self._ai_js_urls: Set[str] = set()
        self._ai_saved_js_hashes: Set[str] = set()
        self._ai_saved_js_files: Dict[str, str] = {}

        self.deep_endpoints = deep_endpoints
        self.verbose = False  # set via CLI

        # v4.4 new modules
        self.fuzz = fuzz
        self.fuzz_wordlist_file = fuzz_wordlist_file
        self.fuzz_max = fuzz_max
        self.google_dorks = google_dorks
        self.probe_firebase = probe_firebase

        # v4.5 new
        self.probe_sitemap = probe_sitemap
        self.min_confidence = min_confidence

        # Thread controls
        self.threads = max(1, int(threads))
        self.asset_threads = max(1, int(asset_threads if asset_threads is not None else self.threads))
        self.crawl_threads = max(1, int(crawl_threads if crawl_threads is not None else min(self.threads, 10)))
        self.authz_threads = max(1, int(authz_threads if authz_threads is not None else min(self.threads, 20)))
        self.deep_threads = max(1, int(deep_threads if deep_threads is not None else min(self.threads, 10)))
        self.fuzz_thread_count = max(1, int(fuzz_threads if fuzz_threads is not None else min(self.threads, 20)))

        safe_mkdir(self.out_dir)
        safe_mkdir(os.path.join(self.out_dir, "routes"))
        safe_mkdir(os.path.join(self.out_dir, "screens"))

        # report template file
        self.template_path = os.path.join(self.out_dir, "report.template.html")
        self._ensure_template()

        # Thread-local session
        self._tls = threading.local()

        self._results_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self._maps_lock = threading.Lock()
        self._screens_lock = threading.Lock()
        self._ai_lock = threading.Lock()

        self._stop_event = threading.Event()

        self.base_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/122.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        self.base_headers.update(self.extra_headers)

        self.results: Dict[str, Any] = {
            "meta": {
                "tool": f"DarkmLens v{self.VERSION} (Darkmoon)",
                "purpose": "Defensive passive analysis (public exposure review)",
                "disclaimer": "Use only on assets you own or have explicit authorization to test.",
                "timestamp": int(time.time()),
            },
            "url": target_url,
            "final_url": "",
            "server_headers": {},
            "technologies": [],
            "fingerprints": [],
            "backend_hints": [],
            "framework_hints": [],
            "nextjs": {
                "detected": False,
                "buildId": None,
                "page": None,
                "assets": {"scripts": [], "styles": [], "images": []},
            },
            "inventory": {
                "internal_links": [],
                "routes_full_urls": [],
                "assets": {"scripts": [], "styles": [], "images": []},
            },
            "crawl": {
                "enabled": crawl_pages,
                "max_pages": max_pages,
                "max_depth": max_depth,
                "visited_pages": [],
                "access_matrix": [],
            },
            "endpoints": {
                "absolute": [],
                "relative": [],
                "graphql": [],
                "websocket": [],
                "base_urls": [],
                "requests_inferred": [],
                "probed_get": [],
                # v4.5 new buckets
                "tanstack_query": [],
                "rtk_endpoints": [],
                "graphql_operations": [],
                "spa_routes": [],
            },
            "firebase": {
                "detected": False,
                "configs": [],
                "configs_parsed": [],
                "firestore_rest": [],
                "rtdb": [],
                "collections_probable": [],
                "hints": [],
            },
            "stack_summary": {
                "app_type": None,
                "frontend_frameworks": [],
                "backend_frameworks": [],
                "services": [],
            },
            "third_party_services": {
                "supabase": {"detected": False, "urls": [], "tables": [], "key_hints": []},
                "auth0": {"detected": False, "domains": []},
                "clerk": {"detected": False},
                "stripe": {"detected": False, "public_keys": []},
                "mixpanel": {"detected": False},
                "intercom": {"detected": False},
                "pusher": {"detected": False},
                "algolia": {"detected": False},
                "google_maps": {"detected": False},
                "mapbox": {"detected": False, "tokens": []},
                "twilio": {"detected": False},
                "onesignal": {"detected": False},
                "recaptcha": {"detected": False},
                "hotjar": {"detected": False},
                "datadog": {"detected": False},
                "launchdarkly": {"detected": False},
                "amplitude": {"detected": False},
                "posthog": {"detected": False},
            },
            "exposed_configs": {
                "aws_amplify_cognito": [],
                "aws_appsync_amplify": [],
                "sentry": [],
                "google_analytics": [],
                "segment": [],
                "other": [],
            },
            "authz_audit": {
                "enabled": audit_authz,
                "max_routes": authz_max_routes,
                "take_screenshots": authz_take_screenshots,
                "items": [],
            },
            "screenshots": {
                "main": None,
                "routes": [],
            },
            "notes": [],
            "fuzzing": {
                "enabled": fuzz,
                "paths_tested": 0,
                "found": [],
                "dir_listings": [],
            },
            "google_dorks": {
                "domain": "",
                "queries": [],
                "ip_blocked": False,
            },
            "firebase_probing": {
                "enabled": probe_firebase,
                "firestore_open": [],
                "rtdb_open": [],
                "storage_open": [],
            },
            "stats": {
                "assets_fetched": 0,
                "maps_found": 0,
                "maps_fetched": 0,
                "pages_visited": 0,
                "authz_routes_tested": 0,
                "fuzz_paths_tested": 0,
                "fuzz_found": 0,
            },
            "reactscan": {
                "enabled": True,
                "tech_results": [],
                "libs_results": [],
                "files_results": [],
                "map_results": [],
                "cve_results": [],
                "active_cve_results": [],
            },
            "ai_extraction": {
                "backend_structure": "",
                "base_urls": [],
                "api_calls": [],
                "other_findings": [],
                "credentials": [],
                "firebase_config_reconstructed": ""
            },
        }

    # -----------------------------
    # Template
    # -----------------------------
    def _ensure_template(self):
        write_text_file(self.template_path, DEFAULT_REPORT_TEMPLATE)

    # -----------------------------
    # UI
    # -----------------------------
    def print_banner(self):
        print(f"{Fore.CYAN}========================================")
        print(f"{Fore.MAGENTA}   DarkmLens v{self.VERSION}  |  Darkmoon | Red Team Barranquilla")
        print(f"{Fore.CYAN}========================================")
        print(f"{Fore.YELLOW}Uso autorizado únicamente. Análisis pasivo.\n")
        print(f"{Fore.CYAN}Threads: global={self.threads} assets={self.asset_threads} crawl={self.crawl_threads} authz={self.authz_threads} deep={self.deep_threads} fuzz={self.fuzz_thread_count}")
        features = []
        if self.fuzz: features.append("FUZZ")
        if self.google_dorks: features.append("DORKS")
        if self.probe_firebase: features.append("FIREBASE-PROBE")
        if self.deep_endpoints: features.append("DEEP")
        if self.audit_authz: features.append("AUTHZ")
        print(f"{Fore.CYAN}Modules: {', '.join(features) if features else 'default'}\n")

    # -----------------------------
    # Thread-local session
    # -----------------------------
    def _get_session(self) -> requests.Session:
        sess = getattr(self._tls, "session", None)
        if sess is None:
            sess = requests.Session()
            sess.headers.update(self.base_headers)
            self._tls.session = sess
        return sess

    # -----------------------------
    # Network
    # -----------------------------
    def fetch(self, url: str) -> Optional[FetchResult]:
        if self._stop_event.is_set():
            return None
        try:
            if self.verbose:
                print(f"{Fore.CYAN}[fetch] {url}")
            t0 = time.time()
            sess = self._get_session()
            r = sess.get(url, timeout=self.request_timeout, allow_redirects=True, verify=False)
            elapsed_ms = int((time.time() - t0) * 1000)
            ct = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            return FetchResult(url=r.url, status=r.status_code, content_type=ct, text=r.text or "", headers=dict(r.headers), elapsed_ms=elapsed_ms)
        except Exception as e:
            with self._results_lock:
                self.results["notes"].append(f"Fetch error {url}: {e}")
            return None

    # -----------------------------
    # Detection
    # -----------------------------
    def identify_tech_wappalyzer(self):
        if not HAS_WAPPALYZER:
            with self._results_lock:
                self.results["notes"].append("Wappalyzer no instalado (opcional).")
            return
        print(f"[*] Identificando tecnologías (Wappalyzer) en {self.target_url}...")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                wappalyzer = Wappalyzer.latest()
                webpage = WebPage.new_from_url(self.target_url)
                techs = list(wappalyzer.analyze(webpage))
                with self._results_lock:
                    self.results["technologies"].extend(techs)
        except Exception as e:
            with self._results_lock:
                self.results["notes"].append(f"Wappalyzer error: {e}")

    def fingerprint_html_and_headers(self, html: str, headers: Dict[str, str]):
        fp: List[str] = []
        backend: List[str] = []
        fw: List[str] = []

        hlow = (html or "").lower()

        if "/_next/static/" in (html or "") or 'id="__NEXT_DATA__"' in (html or ""):
            fp.append("Next.js (heurístico)")
            with self._results_lock:
                self.results["nextjs"]["detected"] = True

        if "data-reactroot" in (html or "") or "react" in hlow:
            fp.append("React (heurístico)")

        if "data-emotion" in (html or "") or "mui" in (html or ""):
            fp.append("MUI/Emotion (heurístico)")

        if self.ANGULAR_HINT_RE.search(html or ""):
            fw.append("Angular (heurístico)")
        if self.VUE_HINT_RE.search(html or ""):
            fw.append("Vue (heurístico)")
        if self.SVELTE_HINT_RE.search(html or ""):
            fw.append("Svelte (heurístico)")
        if self.NUxT_HINT_RE.search(html or ""):
            fw.append("Nuxt (heurístico)")
        if self.REMIX_HINT_RE.search(html or ""):
            fw.append("Remix (heurístico)")
        if self.GATSBY_HINT_RE.search(html or ""):
            fw.append("Gatsby (heurístico)")
        if self.ASTRO_HINT_RE.search(html or ""):
            fw.append("Astro (heurístico)")

        # Backend framework detection from HTML/headers
        if self.DJANGO_HINTS_RE.search(html or ""):
            backend.append("Django (Python) (heurístico)")
        if self.FLASK_HINTS_RE.search(html or ""):
            backend.append("Flask (Python) (heurístico)")
        if self.FASTAPI_HINTS_RE.search(html or ""):
            backend.append("FastAPI (Python) (heurístico)")
        if self.LARAVEL_HINTS_RE.search(html or ""):
            backend.append("Laravel (PHP) (heurístico)")
        if self.RAILS_HINTS_RE.search(html or ""):
            backend.append("Ruby on Rails (heurístico)")
        if self.SPRING_HINTS_RE.search(html or ""):
            backend.append("Spring Boot (Java) (heurístico)")
        if self.DOTNET_HINTS_RE.search(html or ""):
            backend.append("ASP.NET / .NET (heurístico)")
        if self.WORDPRESS_HINTS_RE.search(html or ""):
            backend.append("WordPress (PHP) (heurístico)")
        if self.SHOPIFY_HINTS_RE.search(html or ""):
            backend.append("Shopify (heurístico)")

        # Also check headers for backend hints
        for h_name, h_val in (headers or {}).items():
            hl = h_name.lower()
            hv = (h_val or "").lower()
            if hl == "x-powered-by":
                if "express" in hv:
                    backend.append("Express.js / Node.js (x-powered-by)")
                elif "php" in hv:
                    backend.append(f"PHP ({h_val}) (x-powered-by)")
                elif "asp.net" in hv:
                    backend.append(f"ASP.NET ({h_val}) (x-powered-by)")
            if hl == "server":
                if "gunicorn" in hv or "uvicorn" in hv:
                    backend.append(f"Python WSGI/ASGI ({h_val}) (server header)")
                if "tomcat" in hv:
                    backend.append(f"Java/Tomcat ({h_val}) (server header)")

        sec = []
        for h in ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
                  "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]:
            if h in headers:
                sec.append(h)
        if sec:
            fp.append("Security headers present: " + ", ".join(sec))

        x_powered = headers.get("X-Powered-By", "") or headers.get("x-powered-by", "")
        server = headers.get("Server", "") or headers.get("server", "")
        set_cookie = headers.get("Set-Cookie", "") or headers.get("set-cookie", "")

        if x_powered:
            backend.append(f"X-Powered-By: {x_powered}")
        if server:
            backend.append(f"Server: {server}")

        if "JSESSIONID" in set_cookie:
            backend.append("Cookie hint: JSESSIONID (Java/Spring o similares)")
        if "ASP.NET" in set_cookie or ".ASPXAUTH" in set_cookie:
            backend.append("Cookie hint: ASP.NET")
        if "PHPSESSID" in set_cookie:
            backend.append("Cookie hint: PHP")

        via = headers.get("Via", "") or headers.get("via", "")
        x_cache = headers.get("X-Cache", "") or headers.get("x-cache", "")
        if "cloudfront" in (via + " " + x_cache).lower():
            fp.append("AWS CloudFront/CDN (headers)")
        if any(k.lower().startswith("x-amz-") for k in headers.keys()):
            fp.append("AWS x-amz-* headers")

        with self._results_lock:
            self.results["fingerprints"].extend(fp)
            self.results["backend_hints"].extend(backend)
            self.results["framework_hints"].extend(fw)

    # -----------------------------
    # Findings helpers
    # -----------------------------
    def add_finding(self, bucket: List[dict], data: dict):
        with self._results_lock:
            bucket.append(data)

    def looks_like_real_route(self, p: str) -> bool:
        if not p:
            return False
        if len(p) > 180:
            return False
        if " " in p:
            return False
        if p.startswith("//"):
            return False
        if p in ["/", "/#", "/./", "/*", "//", "/$"]:
            return False
        if self.ASSET_EXT_RE.match(p):
            return False
        if self.BAD_ROUTE_CHARS_RE.search(p):
            return False
        if self.BAD_ROUTE_PATTERNS_RE.search(p):
            return False
        if "/>" in p or "</" in p:
            return False
        if p.endswith(",") or p.endswith(":") or p.endswith(";"):
            return False
        return True

    def _normalize_route_to_path(self, raw: str) -> Optional[str]:
        if not raw:
            return None
        raw = raw.strip()
        if raw.lower().startswith(("mailto:", "tel:", "javascript:", "data:")):
            return None

        if raw.startswith("http://") or raw.startswith("https://"):
            p = urlparse(raw)
            return p.path or "/"

        if raw.startswith("./"):
            raw = raw[1:]
        if not raw.startswith("/"):
            raw = "/" + raw

        p = urlparse(raw)
        return p.path or "/"

    # -----------------------------
    # Request inference helpers
    # -----------------------------
    def _compact_hint(self, s: str, max_len: int = 240) -> str:
        s = (s or "").strip()
        s = re.sub(r"\s+", " ", s)
        return s[:max_len] + ("…" if len(s) > max_len else "")

    def _classify_route_type(self, path: str) -> str:
        """Returns 'backend' if path looks like an API endpoint, else 'frontend'."""
        if self.BACKEND_PATH_RE.match(path or "/"):
            return "backend"
        return "frontend"

    def _parse_firebase_config(self, blob: str) -> dict:
        """Parse a raw Firebase config blob and extract individual fields."""
        out = {}
        for key in ["apiKey", "authDomain", "projectId", "storageBucket",
                    "messagingSenderId", "appId", "measurementId", "databaseURL"]:
            # Handle single quotes, double quotes, and backticks
            m = re.search(rf'["\']?{key}["\']?\s*[:=]\s*["`\']([^"`\']+)["`\']', blob, re.IGNORECASE)
            if m:
                out[key] = m.group(1)
        return out

    def _detect_third_party(self, text: str, source_name: str):
        """Detect third-party services in JS/HTML text."""
        tp = self.results["third_party_services"]

        # Supabase
        if self.SUPABASE_URL_RE.search(text) or self.SUPABASE_KEY_RE.search(text):
            with self._results_lock:
                tp["supabase"]["detected"] = True
            for m in self.SUPABASE_URL_RE.finditer(text):
                url = m.group(0)
                with self._results_lock:
                    if url not in tp["supabase"]["urls"]:
                        tp["supabase"]["urls"].append(url)
            for m in self.SUPABASE_TABLE_RE.finditer(text):
                tbl = m.group(1)
                with self._results_lock:
                    if tbl not in tp["supabase"]["tables"]:
                        tp["supabase"]["tables"].append(tbl)
            if self.SUPABASE_KEY_RE.search(text):
                with self._results_lock:
                    if source_name not in tp["supabase"]["key_hints"]:
                        tp["supabase"]["key_hints"].append(source_name)

        # Auth0
        if self.AUTH0_HINT_RE.search(text) or self.AUTH0_DOMAIN_RE.search(text):
            with self._results_lock:
                tp["auth0"]["detected"] = True
            for m in self.AUTH0_DOMAIN_RE.finditer(text):
                dom = m.group(1)
                with self._results_lock:
                    if dom not in tp["auth0"]["domains"]:
                        tp["auth0"]["domains"].append(dom)

        # Clerk
        if self.CLERK_HINT_RE.search(text):
            with self._results_lock:
                tp["clerk"]["detected"] = True

        # Stripe
        if self.STRIPE_HINT_RE.search(text):
            with self._results_lock:
                tp["stripe"]["detected"] = True
        for m in self.STRIPE_KEY_RE.finditer(text):
            key = m.group(1)
            with self._results_lock:
                if key not in tp["stripe"]["public_keys"]:
                    tp["stripe"]["public_keys"].append(key)
                    tp["stripe"]["detected"] = True

        # Mapbox
        if self.MAPBOX_HINT_RE.search(text):
            with self._results_lock:
                tp["mapbox"]["detected"] = True
        for m in self.MAPBOX_TOKEN_RE.finditer(text):
            tok = m.group(1)
            with self._results_lock:
                if tok not in tp["mapbox"]["tokens"]:
                    tp["mapbox"]["tokens"].append(tok)
                    tp["mapbox"]["detected"] = True

        # Simple detections (boolean only)
        simple = [
            ("mixpanel", self.MIXPANEL_RE),
            ("intercom", self.INTERCOM_RE),
            ("pusher", self.PUSHER_RE),
            ("algolia", self.ALGOLIA_RE),
            ("google_maps", self.GMAPS_RE),
            ("twilio", self.TWILIO_RE),
            ("onesignal", self.ONESIGNAL_RE),
            ("recaptcha", self.RECAPTCHA_RE),
            ("hotjar", self.HOTJAR_RE),
            ("datadog", self.DATADOG_RE),
            ("launchdarkly", self.LAUNCHDARKLY_RE),
            ("amplitude", self.AMPLITUDE_RE),
            ("posthog", self.POSTHOG_RE),
        ]
        for name, rx in simple:
            if rx.search(text):
                with self._results_lock:
                    tp[name]["detected"] = True

    def _extract_object_keys_hint(self, obj_text: str, max_keys: int = 25) -> List[str]:
        if not obj_text:
            return []
        keys = re.findall(r'["\']?([a-zA-Z_][a-zA-Z0-9_-]{0,60})["\']?\s*:', obj_text)
        out = []
        seen = set()
        for k in keys:
            if k not in seen:
                out.append(k)
                seen.add(k)
            if len(out) >= max_keys:
                break
        return out

    def infer_requests_from_text(self, text: str, base: str, source_name: str):
        # fetch("url", { method, headers, body })
        for m in self.FETCH_CALL_RE.finditer(text):
            url = m.group("url")
            opts = m.group("opts") or ""
            ln = line_number_from_index(text, m.start())

            method = "GET"
            mm = self.FETCH_METHOD_RE.search(opts)
            if mm:
                method = mm.group("m").upper()

            body_hint = ""
            body_keys = []
            bm = self.FETCH_BODY_RE.search(opts)
            if bm:
                rawb = bm.group("b")
                body_hint = self._compact_hint(rawb, 260)
                if "JSON.stringify" in rawb:
                    km = re.search(r'JSON\.stringify\s*\(\s*(\{.*?\})\s*\)', rawb, re.DOTALL)
                    if km:
                        body_keys = self._extract_object_keys_hint(km.group(1), max_keys=30)

            headers_hint = ""
            hm = self.FETCH_HEADERS_RE.search(opts)
            if hm:
                headers_hint = self._compact_hint(hm.group("h"), 260)

            full = urljoin(base, url) if url.startswith("/") else url
            params = extract_query_params(full)
            start_ctx = max(0, m.start() - 120)
            end_ctx = min(len(text), m.end() + 200)
            ctx_snippet = text[start_ctx:end_ctx]
            confidence = self._score_api_call_probability(url, ctx_snippet + opts)

            self.add_finding(self.results["endpoints"]["requests_inferred"], {
                "method": method,
                "url_or_path": url,
                "full_url": full,
                "params": params,
                "body_keys": body_keys or [],
                "body_hint": body_hint or None,
                "headers_hint": headers_hint or None,
                "found_in": source_name,
                "line": ln,
                "evidence": "fetch(...)",
                "confidence": confidence,
            })

        # axios.get/post/put/delete(...)
        for m in self.AXIOS_SHORT_RE.finditer(text):
            meth = m.group(1).upper()
            url = m.group("url")
            ln = line_number_from_index(text, m.start())
            full = urljoin(base, url) if url.startswith("/") else url
            start_ctx = max(0, m.start() - 80)
            end_ctx = min(len(text), m.end() + 150)
            ctx_snippet = text[start_ctx:end_ctx]
            confidence = self._score_api_call_probability(url, ctx_snippet)
            self.add_finding(self.results["endpoints"]["requests_inferred"], {
                "method": meth,
                "url_or_path": url,
                "full_url": full,
                "params": extract_query_params(full),
                "body_keys": [],
                "body_hint": None,
                "headers_hint": None,
                "found_in": source_name,
                "line": ln,
                "evidence": f"axios.{meth.lower()}(...)",
                "confidence": confidence,
            })

        # axios({ url, method, params, data, headers })
        for m in self.AXIOS_OBJ_RE.finditer(text):
            obj = m.group("obj") or ""
            ln = line_number_from_index(text, m.start())

            mu = self.AXIOS_URL_IN_OBJ_RE.search(obj)
            if not mu:
                continue
            url = mu.group("url")

            mm = self.AXIOS_METHOD_IN_OBJ_RE.search(obj)
            method = mm.group("m").upper() if mm else "UNKNOWN"

            full = urljoin(base, url) if url.startswith("/") else url
            params = extract_query_params(full)

            mp = self.AXIOS_PARAMS_IN_OBJ_RE.search(obj)
            if mp:
                keys = self._extract_object_keys_hint(mp.group("p")[:1400], max_keys=30)
                for k in keys:
                    if k not in params:
                        params.append(k)
                params = sorted(set(params))

            body_keys = []
            body_hint = None
            md = self.AXIOS_DATA_IN_OBJ_RE.search(obj)
            if md:
                rawd = md.group("d")
                hint = self._compact_hint(rawd, 260)
                if rawd.strip().startswith("{"):
                    body_keys = self._extract_object_keys_hint(rawd, max_keys=30)
                body_hint = hint

            headers_hint = None
            mh = self.AXIOS_HEADERS_IN_OBJ_RE.search(obj)
            if mh:
                headers_hint = self._compact_hint(mh.group("h"), 260)

            ctx_ax = text[max(0, m.start()-100):min(len(text), m.end()+150)]
            confidence_ax = self._score_api_call_probability(url, ctx_ax)
            self.add_finding(self.results["endpoints"]["requests_inferred"], {
                "method": method,
                "url_or_path": url,
                "full_url": full,
                "params": params,
                "body_keys": body_keys or [],
                "body_hint": body_hint,
                "headers_hint": headers_hint,
                "found_in": source_name,
                "line": ln,
                "evidence": "axios({ ... })",
                "confidence": confidence_ax,
            })

        # URLSearchParams({a:1,b:2})
        for m in self.URLSEARCHPARAMS_OBJ_RE.finditer(text):
            obj = m.group("obj") or ""
            ln = line_number_from_index(text, m.start())
            keys = self._extract_object_keys_hint(obj, max_keys=40)
            if keys:
                self.add_finding(self.results["endpoints"]["requests_inferred"], {
                    "method": "UNKNOWN",
                    "url_or_path": "(URLSearchParams)",
                    "full_url": "",
                    "params": sorted(set(keys)),
                    "body_keys": [],
                    "body_hint": "URLSearchParams({...})",
                    "headers_hint": None,
                    "found_in": source_name,
                    "line": ln,
                    "evidence": "URLSearchParams({...})",
                })

    # -----------------------------
    # Extractors
    # -----------------------------
    def extract_routes_from_dom(self, soup: BeautifulSoup, base: str, page_url: str):
        def add_dom_url(raw: str, tag: str):
            if not raw:
                return
            raw = raw.strip()
            if raw.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
                return
            u = urljoin(base, raw)
            if not same_origin(u, base):
                return
            if self.ASSET_EXT_RE.match(u):
                return
            path = urlparse(u).path or "/"
            if not self.looks_like_real_route(path):
                return
            self.add_finding(self.results["inventory"]["routes_full_urls"], {
                "path": path,
                "full_url": u,
                "found_in": f"DOM:{tag} @ {page_url}",
                "line": None
            })

        for a in soup.find_all("a", href=True):
            add_dom_url(a.get("href"), "a[href]")
        for f in soup.find_all("form", action=True):
            add_dom_url(f.get("action"), "form[action]")
        for m in soup.find_all("meta"):
            http_equiv = (m.get("http-equiv") or "").lower()
            if http_equiv == "refresh":
                content = m.get("content") or ""
                parts = content.split("url=")
                if len(parts) > 1:
                    add_dom_url(parts[-1].strip(), "meta[refresh]")

    def _extract_js_navigation_routes(self, text: str, base: str, source_name: str, source_kind: str):
        for rx in self.JS_NAV_RE:
            for m in rx.finditer(text):
                ln = line_number_from_index(text, m.start())

                if "arg" in m.groupdict() and m.groupdict().get("arg"):
                    arg = m.group("arg")
                    if arg.strip().startswith("["):
                        items = re.findall(r'["\']([^"\']+)["\']', arg)
                        if items:
                            if items[0].startswith("/"):
                                raw = items[0]
                            else:
                                raw = "/" + "/".join([x.strip("/ ") for x in items if x.strip()])
                            path = self._normalize_route_to_path(raw)
                            if path and self.looks_like_real_route(path):
                                full = urljoin(base, path)
                                self.add_finding(self.results["inventory"]["routes_full_urls"], {
                                    "path": path,
                                    "full_url": full,
                                    "found_in": f"{source_kind.upper()}: {source_name} | js-nav",
                                    "line": ln
                                })
                    continue

                rawu = m.groupdict().get("u") or ""
                if not rawu:
                    continue

                path = self._normalize_route_to_path(rawu)
                if not path:
                    continue

                if not self.looks_like_real_route(path):
                    if not re.search(r'\.html?$', path, re.IGNORECASE):
                        continue

                full = urljoin(base, path)
                if same_origin(full, base):
                    self.add_finding(self.results["inventory"]["routes_full_urls"], {
                        "path": path,
                        "full_url": full,
                        "found_in": f"{source_kind.upper()}: {source_name} | js-nav",
                        "line": ln
                    })

    def _print_ai_findings_summary(self, file_label: str):
        """Print partial summary of findings after processing each JS chunk."""
        with self._results_lock:
            api_calls = len(self.results.get("ai_extraction", {}).get("api_calls", []))
            credentials = len(self.results.get("ai_extraction", {}).get("credentials", []))
            other_findings = len(self.results.get("ai_extraction", {}).get("other_findings", []))
            base_urls = len(self.results.get("ai_extraction", {}).get("base_urls", []))
            endpoints_inferred = len(self.results.get("endpoints", {}).get("requests_inferred", []))
            secrets = len(self.results.get("ai_extraction", {}).get("secrets", []))
            
            total = api_calls + credentials + other_findings + base_urls + endpoints_inferred + secrets
        
        if total > 0:
            summary_parts = []
            if api_calls > 0:
                summary_parts.append(f"{Fore.GREEN}API:{api_calls}{Style.RESET_ALL}")
            if credentials > 0:
                summary_parts.append(f"{Fore.RED}CREDS:{credentials}{Style.RESET_ALL}")
            if other_findings > 0:
                summary_parts.append(f"{Fore.YELLOW}Otros:{other_findings}{Style.RESET_ALL}")
            if base_urls > 0:
                summary_parts.append(f"{Fore.CYAN}URLs:{base_urls}{Style.RESET_ALL}")
            if endpoints_inferred > 0:
                summary_parts.append(f"{Fore.CYAN}Endpoints:{endpoints_inferred}{Style.RESET_ALL}")
            if secrets > 0:
                summary_parts.append(f"{Fore.RED}Secrets:{secrets}{Style.RESET_ALL}")
            
            summary = " | ".join(summary_parts)
            print(f"{Fore.CYAN}[AI] Hallazgos acumulados: {summary} {Fore.CYAN}[Total: {total}]{Style.RESET_ALL}")

    def _analyze_js_with_ai(self, text: str, source_url: str):
        """Usa Claude o Ollama para analizar archivos JS y extraer endpoints, keys y estructura del backend."""
        if not text:
            return

        if getattr(self, 'ai_provider', 'claude') == 'claude' and not self.ai_api_key:
            print(f"{Fore.YELLOW}[AI] --ai-api-key no proporcionado. Saltando análisis Claude.")
            return

        # Truncar JS a 50000 chars para no exceder el contexto (minified puede ser enorme)
        is_ollama = getattr(self, 'ai_provider', 'claude') == 'ollama'
        is_lm_studio = getattr(self, 'ai_provider', 'claude') == 'lm_studio'
        # Ollama local models usually have smaller context limits than Claude. 
        # On Virtual Machines w/o GPUs, reading large prompts takes quadratic time.
        if is_ollama:
            max_chars = 10000
        elif is_lm_studio:
            max_chars = 80000 # Send up to ~20k tokens for local models with high context limits
        else:
            max_chars = 50000
            
        file_label = source_url.split("/")[-1] or source_url
        if is_ollama:
            engine_str = f"Ollama ({self.ai_model})"
        elif is_lm_studio:
            engine_str = f"LM Studio ({self.ai_model})"
        else:
            engine_str = "Claude"

        chunks = [text[i:i+max_chars] for i in range(0, len(text), max_chars)]
        total_chunks = len(chunks)
        empty_array_limit = 3
        empty_array_hits = 0
        accepted_chunks = 0

        # Collect already-detected backend base URLs to use as context for the AI
        known_backends: list = []
        with self._results_lock:
            for entry in (self.results.get("ai_extraction", {}).get("base_urls") or []):
                u = entry.get("url") if isinstance(entry, dict) else str(entry)
                if u and u not in known_backends:
                    known_backends.append(u)
            for entry in (self.results.get("endpoints", {}).get("base_urls") or []):
                u = entry.get("url") if isinstance(entry, dict) else str(entry)
                if u and u not in known_backends:
                    known_backends.append(u)

        known_backends_block = ""
        if known_backends:
            backends_list = "\n".join(f"  - {u}" for u in known_backends[:20])
            known_backends_block = (
                f"\nBACKENDS YA DETECTADOS (usa estos como contexto obligatorio):\n"
                f"{backends_list}\n"
                f"Para CADA uno de los backends listados arriba, busca en el código TODAS las llamadas HTTP que los usan "
                f"y extrae: método (GET/POST/PUT/DELETE/PATCH), query params en la URL, campos del body (JSON/FormData), "
                f"headers enviados, y desde qué función o componente se invoca.\n"
            )

        for c_idx, js_chunk in enumerate(chunks):
            chunk_label = f" (Parte {c_idx+1}/{total_chunks})" if total_chunks > 1 else ""

            prompt = (
                f"Actúa como un analista rápido de JavaScript y backend exposure.\n"
                f"Analiza solo este fragmento del archivo '{source_url}'{chunk_label}.\n"
                f"{known_backends_block}\n"
                f"REGLAS: usa solo datos literales del código; no inventes nada; no uses ejemplos ni placeholders; si no hay datos reales usa [] o \"\".\n"
                f"Prioriza velocidad y precisión. Devuelve solo lo que realmente encuentres en este fragmento.\n\n"
                f"IMPORTANTE: NO devuelvas un campo 'code'. NO resumas el archivo. SOLO devuelve el JSON del esquema pedido.\n"
                f"Saca URLs base, llamadas HTTP reales (url/ruta, método, query params, body, headers, función/componente), credenciales reales, Firebase real, endpoints admin/GraphQL/WebSocket/servicios externos.\n"
                f"Formato de salida: JSON válido con esta estructura:\n"
                f"{{\n"
                f"  \"backend_structure\": \"\",\n"
                f"  \"base_urls\": [],\n"
                f"  \"firebase_config_reconstructed\": \"\",\n"
                f"  \"api_calls\": [],\n"
                f"  \"credentials\": [],\n"
                f"  \"other_findings\": [],\n"
                f"  \"endpoints\": [],\n"
                f"  \"secrets\": []\n"
                f"}}\n\n"
                f"CÓDIGO JAVASCRIPT:\n{js_chunk}"
            )

            try:
                if is_lm_studio:
                    payload = {
                         "model": self.ai_model,
                         "messages": [
                             {"role": "system", "content": "You are a security analyzer. You MUST output ONLY valid JSON without Markdown blocks, no explanations, no text before or after."},
                             {"role": "user", "content": prompt}
                         ],
                         "temperature": 0.1,
                         "max_tokens": 4096,
                         "response_format": {"type": "text"},
                         "stream": True
                    }
                    base_url = getattr(self, 'lm_studio_url', "http://127.0.0.1:1234")
                    with getattr(self, '_ai_lock', threading.Lock()):
                        print(f"{Fore.CYAN}[AI] Analizando JS con {engine_str}: {file_label}{chunk_label} ({len(js_chunk)} enviados)")
                        print(f"{Fore.MAGENTA}[AI] [LM Studio] Iniciando generación...{Style.RESET_ALL}")
                        r = requests.post(f"{base_url}/v1/chat/completions", json=payload, stream=True, timeout=1200)
                        response_text = ""
                        if r.status_code == 200:
                            for line in r.iter_lines():
                                if line:
                                    decoded_line = line.decode('utf-8', errors='ignore')
                                    if decoded_line.startswith("data: "):
                                        data_str = decoded_line[6:].strip()
                                        if data_str == "[DONE]":
                                            break
                                        try:
                                            chunk = json.loads(data_str)
                                            choices = chunk.get("choices", [])
                                            if choices and "delta" in choices[0]:
                                                part = choices[0]["delta"].get("content", "")
                                                response_text += part
                                        except Exception:
                                            pass
                            print(f"{Fore.CYAN}[AI] [LM Studio] Respuesta recibida ({len(response_text)} chars).")
                        else:
                            print(f"\\n{Fore.RED}[AI] Error HTTP de LM Studio ({r.status_code}): {r.text}")
                            continue
                elif is_ollama:
                    payload = {
                        "model": self.ai_model,
                        "prompt": prompt,
                        "stream": True,
                        "format": "json",
                        "options": {
                            "num_ctx": 4096,
                            "temperature": 0.1,
                            "num_predict": 2048
                        }
                    }
                    
                    with getattr(self, '_ai_lock', threading.Lock()):
                        print(f"{Fore.CYAN}[AI] Analizando JS con {engine_str}: {file_label}{chunk_label} ({len(js_chunk)} enviados)")
                        print(f"{Fore.MAGENTA}[AI] [Ollama] Iniciando generación...{Style.RESET_ALL}")
                        r = requests.post(f"{self.ollama_url}/api/generate", json=payload, stream=True, timeout=1200)
                        response_text = ""
                        if r.status_code == 200:
                            for line in r.iter_lines():
                                if line:
                                    try:
                                        chunk = json.loads(line)
                                        part = chunk.get("response", "")
                                        response_text += part
                                    except Exception:
                                        pass
                            print(f"{Fore.CYAN}[AI] [Ollama] Respuesta recibida ({len(response_text)} chars).")
                        else:
                            print(f"\\n{Fore.RED}[AI] Error HTTP de Ollama ({r.status_code}): {r.text}")
                            continue
                else:
                    print(f"{Fore.CYAN}[AI] Analizando JS con {engine_str}: {file_label}{chunk_label} ({len(js_chunk)} enviados)")
                    r = requests.post(
                        "https://api.anthropic.com/v1/messages",
                        headers={
                            "x-api-key": self.ai_api_key,
                            "anthropic-version": "2023-06-01",
                            "content-type": "application/json",
                        },
                        json={
                            "model": "claude-3-5-sonnet-20241022",
                            "max_tokens": 4096,
                            "messages": [{"role": "user", "content": prompt}]
                        },
                        timeout=90
                    )

                    if r.status_code == 200:
                        resp = r.json()
                        response_text = ""
                        for block in resp.get("content", []):
                            if block.get("type") == "text":
                                response_text += block.get("text", "")
                    else:
                        try:
                            err = r.json()
                            print(f"{Fore.RED}[AI] Error HTTP de Claude ({r.status_code}): {err}")
                        except Exception:
                            print(f"{Fore.RED}[AI] Error HTTP de Claude ({r.status_code}): {r.text}")
                        continue

                # Strip possible markdown code fences and conversational boilerplate
                response_text = self._extract_first_json_object(response_text)
                    
                if response_text:
                    try:
                        data = json.loads(response_text)
                        if not self._is_valid_ai_extraction_schema(data):
                            print(f"{Fore.YELLOW}[AI] Respuesta descartada por esquema inválido ({engine_str}) en {file_label}{chunk_label}.")
                            continue

                        list_fields = ("base_urls", "api_calls", "credentials", "other_findings", "endpoints", "secrets")
                        empty_fields = [
                            key for key in list_fields
                            if isinstance(data.get(key), list) and len(data.get(key)) == 0
                        ]
                        if empty_fields:
                            empty_array_hits += 1
                            print(
                                f"{Fore.YELLOW}[AI] Respuesta omitida por arrays vacíos en {file_label}{chunk_label}: "
                                f"{', '.join(empty_fields)} ({empty_array_hits}/{empty_array_limit})."
                            )
                            if empty_array_hits >= empty_array_limit:
                                print(
                                    f"{Fore.YELLOW}[AI] Se alcanzó el límite de respuestas con arrays vacíos "
                                    f"en {file_label}. Saltando al siguiente JS."
                                )
                                break
                            continue

                        accepted_chunks += 1
                        print(f"{Fore.GREEN}[AI] Respuesta válida sin arrays vacíos en {file_label}{chunk_label}.")

                        # Stamp source file for traceability
                        for item in data.get("api_calls", []):
                            item["source_file"] = file_label + chunk_label
                        for item in data.get("other_findings", []):
                            item["source_file"] = file_label + chunk_label
                        data["_source_file"] = file_label + chunk_label
                        
                        self._merge_ai_extraction_payload(data, file_label + chunk_label)
                        self._print_ai_findings_summary(file_label + chunk_label)
                    except Exception as parse_e:
                        print(f"{Fore.RED}[AI] Error parseando JSON de {engine_str}: {parse_e}\\nRaw output: {response_text}")
            except Exception as api_e:
                print(f"{Fore.YELLOW}[AI] Fallo al contactar API local/remota: {api_e}")

        print(
            f"{Fore.CYAN}[AI] Fin de {file_label}: "
            f"válidas sin arrays vacíos={accepted_chunks}, omitidas por arrays vacíos={empty_array_hits}."
        )

    def _prepare_ai_js_workspace(self):
        js_dir = os.path.join(self.out_dir, "ai_js_downloads")
        if os.path.isdir(js_dir):
            try:
                shutil.rmtree(js_dir)
            except Exception as e:
                print(f"{Fore.YELLOW}[AI] No pude limpiar ai_js_downloads: {e}")
        safe_mkdir(js_dir)
        with self._ai_js_urls_lock:
            self._ai_js_urls = set()
        with self._ai_saved_js_lock:
            self._ai_saved_js_hashes = set()
            self._ai_saved_js_files = {}

    def _queue_ai_js_url(self, url: str):
        if not url:
            return
        try:
            normalized = normalize_url(url)
        except Exception:
            normalized = url
        with self._ai_js_urls_lock:
            self._ai_js_urls.add(normalized)

    def _queue_ai_js_urls_from_html(self, html: str, page_url: str, base_origin: str):
        if not self.ai_js_extract or not html:
            return
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return

        for s in soup.find_all("script", src=True):
            src = (s.get("src") or "").strip()
            if not src:
                continue
            u = urljoin(page_url, src)
            if same_origin(u, base_origin):
                self._queue_ai_js_url(u)

    def _download_all_ai_js_assets(self, base_origin: str):
        if not self.ai_js_extract:
            return

        with self._ai_js_urls_lock:
            pending_urls = sorted(self._ai_js_urls)

        if not pending_urls:
            print(f"{Fore.YELLOW}[AI] No encontré scripts externos same-origin para descargar localmente.")
            return

        print(f"{Fore.CYAN}[AI] Descargando localmente {len(pending_urls)} JS para análisis con {self.ai_provider}...")

        def worker(u: str):
            ar = self.fetch(u)
            if self.sleep_between:
                time.sleep(self.sleep_between)
            if not ar or ar.status >= 400 or not ar.text:
                return False
            ctype = (ar.content_type or "").lower()
            looks_js = (
                u.lower().endswith(".js")
                or "javascript" in ctype
                or "ecmascript" in ctype
                or "module" in ctype
            )
            if not looks_js:
                return False
            self.extract_from_text(ar.text, base_origin, f"AI_ASSET: {u}", source_kind="js")
            return True

        downloaded = 0
        with ThreadPoolExecutor(max_workers=self.asset_threads) as ex:
            futs = [ex.submit(worker, u) for u in pending_urls]
            for fut in as_completed(futs):
                try:
                    if fut.result():
                        downloaded += 1
                except Exception:
                    pass

        print(f"{Fore.GREEN}[AI] JS locales listos: {downloaded}/{len(pending_urls)}")

    def _save_js_for_local_ai(self, text: str, source_url: str):
        if not text:
            return
        js_dir = os.path.join(self.out_dir, "ai_js_downloads")
        safe_mkdir(js_dir)
        clean_url = source_url.split(" ")[-1] if source_url else ""
        fname = safe_filename(clean_url.split("/")[-1] or "script.js")
        if not fname.endswith(".js"):
            fname += ".js"
        fhash = sha1(text)[:10]
        fname = f"{fname}_{fhash}.js"
        full_path = os.path.join(js_dir, fname)

        with self._ai_saved_js_lock:
            if fhash in self._ai_saved_js_hashes:
                return
            self._ai_saved_js_hashes.add(fhash)
            self._ai_saved_js_files[fhash] = fname

        write_text_file(full_path, text)

    def _run_post_crawl_ai_analysis(self):
        if not self.ai_js_extract:
            return
            
        provider = getattr(self, 'ai_provider', 'claude')
        if provider == 'claude_code':
            self._run_claude_code_analyzer()
            return
            
        js_dir = os.path.join(self.out_dir, "ai_js_downloads")
        if not os.path.exists(js_dir) or not os.listdir(js_dir):
            print(f"{Fore.YELLOW}[AI] No se descargaron archivos JS para analizar.")
            return

        js_files = sorted([
            name for name in os.listdir(js_dir)
            if os.path.isfile(os.path.join(js_dir, name)) and name.lower().endswith(".js")
        ])
        
        print(f"\n{Fore.CYAN}[AI] Procesando secuencialmente {len(js_files)} archivos JS descargados con {provider}...")
        
        for name in js_files:
            file_path = os.path.join(js_dir, name)
            try:
                text = read_text_file(file_path)
                self._analyze_js_with_ai(text, name)
                if getattr(self, "sleep_between", 0):
                    time.sleep(self.sleep_between)
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[!] Archivo {name} omitido por el usuario (Ctrl+C). Pasando al siguiente...")
                continue
            except Exception as e:
                print(f"{Fore.RED}[AI] Fallo procesando archivo local {name}: {e}")
        
        # Print summary of findings
        with self._results_lock:
            api_calls = len(self.results.get("ai_extraction", {}).get("api_calls", []))
            credentials = len(self.results.get("ai_extraction", {}).get("credentials", []))
            other_findings = len(self.results.get("ai_extraction", {}).get("other_findings", []))
            base_urls = len(self.results.get("ai_extraction", {}).get("base_urls", []))
            endpoints_inferred = len(self.results.get("endpoints", {}).get("requests_inferred", []))
            secrets = len(self.results.get("ai_extraction", {}).get("secrets", []))
            
            total_incidents = api_calls + credentials + other_findings + base_urls + endpoints_inferred + secrets
        
        print(f"\n{Fore.CYAN}{'='*66}")
        print(f"{Fore.CYAN}[AI] RESUMEN DE INCIDENCIAS ENCONTRADAS:")
        print(f"{Fore.CYAN}{'='*66}")
        if api_calls > 0:
            print(f"{Fore.GREEN}  [+] Llamadas API extraídas: {api_calls}")
        if credentials > 0:
            print(f"{Fore.RED}  [!] Credenciales halladas: {credentials}")
        if other_findings > 0:
            print(f"{Fore.YELLOW}  [*] Otros hallazgos: {other_findings}")
        if base_urls > 0:
            print(f"{Fore.CYAN}  [*] URLs base encontradas: {base_urls}")
        if endpoints_inferred > 0:
            print(f"{Fore.CYAN}  [*] Endpoints inferidos: {endpoints_inferred}")
        if secrets > 0:
            print(f"{Fore.RED}  [!] Secretos detectados: {secrets}")
        
        print(f"{Fore.CYAN}{'-'*66}")
        if total_incidents > 0:
            print(f"{Fore.GREEN}[AI] TOTAL DE INCIDENCIAS: {total_incidents}")
        else:
            print(f"{Fore.YELLOW}[AI] TOTAL DE INCIDENCIAS: 0 (Sin hallazgos en el análisis de JS)")
        print(f"{Fore.CYAN}{'='*66}\n")


    def _read_claude_code_custom_prompt(self) -> str:
        parts: List[str] = []
        prompt_file = (getattr(self, "claude_code_prompt_file", "") or "").strip()
        if prompt_file:
            try:
                file_text = read_text_file(prompt_file).strip()
                if file_text:
                    parts.append(file_text)
            except Exception as e:
                print(f"{Fore.YELLOW}[AI] No pude leer --claude-code-prompt-file: {e}")

        extra_prompt = (getattr(self, "claude_code_extra_prompt", "") or "").strip()
        if extra_prompt:
            parts.append(extra_prompt)

        return "\n\n".join(parts).strip()

    def _build_claude_code_prompt(self, js_files: List[str]) -> str:
        custom_prompt = self._read_claude_code_custom_prompt()
        files_block = "\n".join(f"- {name}" for name in js_files)

        # Inject already-detected backend base URLs as context
        known_backends: list = []
        with self._results_lock:
            for entry in (self.results.get("ai_extraction", {}).get("base_urls") or []):
                u = entry.get("url") if isinstance(entry, dict) else str(entry)
                if u and u not in known_backends:
                    known_backends.append(u)
            for entry in (self.results.get("endpoints", {}).get("base_urls") or []):
                u = entry.get("url") if isinstance(entry, dict) else str(entry)
                if u and u not in known_backends:
                    known_backends.append(u)

        known_backends_block = ""
        if known_backends:
            backends_list = "\n".join(f"  - {u}" for u in known_backends[:20])
            known_backends_block = (
                f"\nBACKENDS YA DETECTADOS (contexto obligatorio):\n{backends_list}\n"
                f"Para CADA backend listado, busca TODAS las llamadas HTTP en los archivos JS y extrae: "
                f"método, query params, campos del body, headers y función/componente que la invoca.\n"
            )

        schema = (
            '{\n'
            '  "backend_structure": "",\n'
            '  "base_urls": [],\n'
            '  "firebase_config_reconstructed": "",\n'
            '  "api_calls": [],\n'
            '  "credentials": [],\n'
            '  "other_findings": [],\n'
            '  "endpoints": [],\n'
            '  "secrets": []\n'
            '}'
        )
        prompt_parts = [
            "Actúa como un analista experto de ciberseguridad y reverse engineering de JavaScript frontend.",
            "Lee TODOS los archivos .js del directorio actual antes de responder. No omitas ninguno.",
            "Correlaciona información entre archivos para reconstruir el backend: helpers HTTP, variables compartidas, base URLs, Firebase, GraphQL, WebSockets y wrappers de API.",
            "Si varios archivos aportan datos del mismo endpoint, consolídalos en una sola entrada.",
            "REGLA MÁS IMPORTANTE: SOLO reporta lo que encuentres LITERALMENTE en el código fuente. "
            "Si un campo no tiene datos reales, usa [] o \"\". "
            "NUNCA inventes URLs, credenciales ni valores. "
            "NUNCA uses placeholders como <YOUR_API_KEY>, example.com, api.localhost.com ni ningún valor de ejemplo. "
            "Si no encuentras nada real, todos los arrays deben ser [] y los strings \"\".",
            known_backends_block,
            "La lista completa de archivos que debes revisar es:",
            files_block,
            "Extrae SOLO información real presente en el código:",
            "0. URLs base del backend REALES: indica en qué constante/variable se guarda y desde qué función/componente se usa.",
            "1. Para CADA llamada HTTP real (fetch, axios, XHR): URL exacta, método, query params reales, campos del body reales, headers reales, y función/componente que la invoca.",
            "2. Credenciales hardcodeadas REALES: Firebase apiKey, AWS keys, JWT secrets, passwords, tokens. Valor COMPLETO literal.",
            "3. Si hay config REAL de Firebase en el código, reconstruye el objeto con los valores REALES en 'firebase_config_reconstructed'.",
            "4. Clasificación del backend: REST, GraphQL, Firebase, WebSocket, Next.js actions, etc.",
            "5. Riesgos reales encontrados: auth bypass, endpoints admin, buckets, webhooks, source maps.",
            "NO abrevies valores reales. NO recortes API keys ni tokens.",
            "Devuelve SOLO JSON válido, sin markdown, sin comentarios y sin texto adicional.",
            "Estructura del JSON (usa [] o \"\" para campos sin datos reales):",
            schema,
        ]
        if custom_prompt:
            prompt_parts.extend([
                "",
                "Instrucciones adicionales del usuario. Debes obedecerlas e integrarlas al análisis:",
                custom_prompt,
            ])
        return "\n".join(prompt_parts).strip()

    # URLs/values that models hallucinate when they find nothing real
    _AI_HALLUCINATION_PATTERNS = (
        "api.localhost.com", "api.backend.com", "api.example.com", "api.x.com",
        "example.com", "localhost.com", "YOUR_API_KEY", "YOUR_AUTH_DOMAIN",
        "YOUR_PROJECT_ID", "YOUR_CREDENTIALS", "YOUR_SECRET", "VALOR_COMPLETO",
        "VALOR_ COMPLETO", "<token>", "<TOKEN>", "<YOUR_", "placeholder",
        "test@test.com", "LoginForm.jsx", "handleSubmit()",
    )

    def _is_ai_hallucination(self, value: str) -> bool:
        if not value or not isinstance(value, str):
            return False
        v = value.strip()
        for pat in self._AI_HALLUCINATION_PATTERNS:
            if pat.lower() in v.lower():
                return True
        return False

    def _merge_ai_extraction_payload(self, data: dict, source_label: str):
        if not isinstance(data, dict):
            return

        if data.get("backend_structure"):
            if not self.results["ai_extraction"]["backend_structure"]:
                self.results["ai_extraction"]["backend_structure"] = data["backend_structure"]
            elif data["backend_structure"] not in self.results["ai_extraction"]["backend_structure"]:
                self.results["ai_extraction"]["backend_structure"] += " | " + data["backend_structure"]

        if isinstance(data.get("base_urls"), list):
            for item in data["base_urls"]:
                if not isinstance(item, dict):
                    continue
                if self._is_ai_hallucination(item.get("url", "")):
                    continue
                if not item.get("source_file"):
                    item["source_file"] = source_label
                self.results["ai_extraction"]["base_urls"].append(item)

        if isinstance(data.get("api_calls"), list):
            for item in data["api_calls"]:
                if not isinstance(item, dict):
                    continue
                if self._is_ai_hallucination(item.get("url", "")):
                    continue
                if not item.get("source_file"):
                    item["source_file"] = source_label
                self.results["ai_extraction"]["api_calls"].append(item)

        if isinstance(data.get("other_findings"), list):
            for item in data["other_findings"]:
                if isinstance(item, dict) and not item.get("source_file"):
                    item["source_file"] = source_label
            self.results["ai_extraction"]["other_findings"].extend(data["other_findings"])

        for ep in (data.get("endpoints", []) or []):
            if not isinstance(ep, str) or not ep or self._is_ai_hallucination(ep):
                continue
            self.add_finding(self.results["endpoints"]["requests_inferred"], {
                "method": "UNKNOWN",
                "url_or_path": ep,
                "full_url": ep,
                "params": [],
                "body_keys": [],
                "body_hint": None,
                "headers_hint": None,
                "found_in": f"[AI Infer] {source_label}",
                "line": 0,
                "evidence": "AI LLM",
                "confidence": 95,
            })

        for sec in (data.get("secrets", []) or []):
            if isinstance(sec, str) and sec and not self._is_ai_hallucination(sec):
                self.add_finding(self.results["exposed_configs"]["other"], {
                    "hint": sec,
                    "found_in": f"[AI Infer] {source_label}",
                    "line": 0
                })

        if isinstance(data.get("credentials"), list):
            for item in data["credentials"]:
                if not isinstance(item, dict):
                    continue
                if self._is_ai_hallucination(item.get("value", "") + item.get("type", "")):
                    continue
                if not item.get("source_file"):
                    item["source_file"] = source_label
                self.results["ai_extraction"]["credentials"].append(item)
                hint = item.get("value") or item.get("description") or str(item)
                self.add_finding(self.results["exposed_configs"]["other"], {
                    "hint": hint,
                    "found_in": f"[AI Cred] {source_label}",
                    "line": 0
                })

        firebase_raw = data.get("firebase_config_reconstructed") or ""
        if firebase_raw and isinstance(firebase_raw, str) and len(firebase_raw) > 10:
            existing = self.results["ai_extraction"].get("firebase_config_reconstructed", "")
            if not existing:
                self.results["ai_extraction"]["firebase_config_reconstructed"] = firebase_raw
            elif firebase_raw not in existing:
                self.results["ai_extraction"]["firebase_config_reconstructed"] += "\n\n// --- " + source_label + " ---\n" + firebase_raw

    def _extract_first_json_object(self, raw_text: str) -> str:
        raw_text = (raw_text or "").strip()
        if not raw_text:
            return ""
        decoder = json.JSONDecoder()
        for i, ch in enumerate(raw_text):
            if ch != "{":
                continue
            try:
                obj, end = decoder.raw_decode(raw_text[i:])
                if isinstance(obj, dict):
                    return raw_text[i:i + end]
            except Exception:
                continue
        return ""

    def _is_valid_ai_extraction_schema(self, data: Any) -> bool:
        """Accept only JSON payloads that look like our expected extraction schema."""
        if not isinstance(data, dict):
            return False

        expected_keys = {
            "backend_structure",
            "base_urls",
            "firebase_config_reconstructed",
            "api_calls",
            "credentials",
            "other_findings",
            "endpoints",
            "secrets",
        }

        # Fast-reject common bad output from small models.
        if "code" in data and not (set(data.keys()) & expected_keys):
            return False

        if not (set(data.keys()) & expected_keys):
            return False

        # Ensure collection fields are lists when present.
        list_fields = ("base_urls", "api_calls", "credentials", "other_findings", "endpoints", "secrets")
        for key in list_fields:
            if key in data and not isinstance(data.get(key), list):
                return False

        return True

    def _run_claude_code_analyzer(self):
        js_dir = os.path.join(self.out_dir, "ai_js_downloads")
        if not os.path.exists(js_dir) or not os.listdir(js_dir):
            print(f"{Fore.YELLOW}[AI] No se descargaron archivos JS para Claude Code.")
            return

        js_files = sorted([
            name for name in os.listdir(js_dir)
            if os.path.isfile(os.path.join(js_dir, name)) and name.lower().endswith(".js")
        ])
        if not js_files:
            print(f"{Fore.YELLOW}[AI] Claude Code no encontró archivos .js para analizar.")
            return

        claude_bin = (getattr(self, "claude_code_bin", "claude") or "claude").strip()
        resolved_bin = shutil.which(claude_bin) or shutil.which("claude")
        if not resolved_bin:
            print(f"{Fore.RED}[AI] No encontré el binario de Claude Code. Instálalo o usa --claude-code-bin.")
            return

        prompt = self._build_claude_code_prompt(js_files)
        timeout_seconds = max(30, int(getattr(self, "claude_code_timeout", 180) or 180))
        command = [resolved_bin, "-p", prompt]

        print(f"\n{Fore.CYAN}[AI] Ejecutando Claude Code sobre {len(js_files)} archivos JS descargados...")
        print(f"{Fore.CYAN}[AI] Binario: {resolved_bin}")
        print(f"{Fore.CYAN}[AI] Timeout: {timeout_seconds}s")
        print(f"{Fore.CYAN}[AI] Prompt length: {len(prompt)} chars")

        stdout_text = ""
        stderr_text = ""
        return_code = None

        try:
            import sys
            import threading
            
            process = subprocess.Popen(
                command,
                cwd=js_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=sys.stdin,
                text=True,
                shell=False,
                bufsize=1,
            )

            stderr_chunks: List[str] = []
            
            def _drain_stderr():
                while True:
                    char = process.stderr.read(1)
                    if not char:
                        break
                    stderr_chunks.append(char)
                    sys.stderr.write(char)
                    sys.stderr.flush()
                    
            t_err = threading.Thread(target=_drain_stderr, daemon=True)
            t_err.start()

            stdout_chunks: List[str] = []
            sys.stdout.write(Fore.MAGENTA)
            sys.stdout.flush()

            while True:
                char = process.stdout.read(1)
                if not char and process.poll() is not None:
                    break
                if char:
                    stdout_chunks.append(char)
                    sys.stdout.write(char)
                    sys.stdout.flush()

            sys.stdout.write(Style.RESET_ALL)
            sys.stdout.flush()
            t_err.join(timeout=2.0)
            process.wait()

            return_code = process.returncode
            stdout_text = "".join(stdout_chunks).strip()
            stderr_text = "".join(stderr_chunks).strip()

        except FileNotFoundError:
            print(f"{Fore.RED}[AI] No se pudo ejecutar Claude Code. Binario no encontrado: {resolved_bin}")
            return
        except Exception as e:
            print(f"{Fore.RED}[AI] Excepción ejecutando Claude Code: {e}")
            return

        stdout_text = (stdout_text or "").strip()
        stderr_text = (stderr_text or "").strip()

        if return_code not in (0, None):
            print(f"\n{Fore.RED}[AI] Claude Code terminó con código {return_code}.")
            if not stdout_text:
                return

        response_text = self._extract_first_json_object(stdout_text)
        if not response_text and stderr_text:
            response_text = self._extract_first_json_object(stderr_text)

        if not response_text:
            raw_path = os.path.join(self.out_dir, "claude_code_raw_output.txt")
            try:
                with open(raw_path, "w", encoding="utf-8", errors="ignore") as fh:
                    fh.write("=== STDOUT ===\n")
                    fh.write(stdout_text)
                    fh.write("\n\n=== STDERR ===\n")
                    fh.write(stderr_text)
                print(f"{Fore.YELLOW}[AI] Claude Code no devolvió JSON parseable. Revisar: {raw_path}")
            except Exception as e:
                print(f"{Fore.YELLOW}[AI] Claude Code no devolvió JSON parseable y no pude guardar salida: {e}")
            return

        try:
            data = json.loads(response_text)
            self._merge_ai_extraction_payload(data, f"Claude Code ({len(js_files)} files)")
        except Exception as parse_e:
            raw_path = os.path.join(self.out_dir, "claude_code_invalid_json.txt")
            try:
                with open(raw_path, "w", encoding="utf-8", errors="ignore") as fh:
                    fh.write(response_text)
                print(f"{Fore.YELLOW}[AI] Guardé el JSON inválido en: {raw_path}")
            except Exception:
                pass
            print(f"{Fore.RED}[AI] Error parseando JSON de Claude Code: {parse_e}")
            return

    def extract_from_text(self, text: str, base: str, source_name: str, source_kind: str):
        if not text:
            return

        if self.ai_js_extract and source_kind == "js":
            self._save_js_for_local_ai(text, source_name)

        if source_kind in ("js", "css", "html"):
            self.infer_requests_from_text(text, base, source_name)

        if source_kind in ("js", "html"):
            self._extract_js_navigation_routes(text, base, source_name, source_kind)

        # v4.5: New extractors
        if source_kind == "js":
            self._extract_spa_routes_from_js(text, base, source_name)
            self._extract_query_library_calls(text, base, source_name)
            self._extract_graphql_operations(text, source_name)
            self._extract_base_url_combinations(text, base, source_name)

        for m in self.WS_RE.finditer(text):
            url = m.group(1)
            ln = line_number_from_index(text, m.start())
            self.add_finding(self.results["endpoints"]["websocket"], {"url": url, "found_in": source_name, "line": ln})

        for m in self.ABS_URL_RE.finditer(text):
            u = m.group(0)
            ln = line_number_from_index(text, m.start())
            lower = u.lower()
            params = extract_query_params(u)

            is_apiish = any(x in lower for x in ["/api/", "/graphql", "/gql", "/v1/", "/v2/", "/v3/", "/oauth", "/auth", "/token", "/services/"])
            if is_apiish:
                self.add_finding(self.results["endpoints"]["absolute"], {"url": u, "params": params, "found_in": source_name, "line": ln})
            if self.GRAPHQL_HINT_RE.search(u):
                self.add_finding(self.results["endpoints"]["graphql"], {"url_or_path": u, "found_in": source_name, "line": ln})

            if "firestore.googleapis.com" in lower:
                with self._results_lock:
                    self.results["firebase"]["detected"] = True
                self.add_finding(self.results["firebase"]["firestore_rest"], {"url": u, "found_in": source_name, "line": ln})
            if ".firebaseio.com" in lower and u.endswith(".json"):
                with self._results_lock:
                    self.results["firebase"]["detected"] = True
                self.add_finding(self.results["firebase"]["rtdb"], {"url": u, "found_in": source_name, "line": ln})

        for m in self.REL_ENDPOINT_RE.finditer(text):
            path = m.group(1)
            ln = line_number_from_index(text, m.start())
            full = urljoin(base, path)
            self.add_finding(self.results["endpoints"]["relative"], {"path": path, "full_url": full, "found_in": source_name, "line": ln})
            if self.GRAPHQL_HINT_RE.search(path):
                self.add_finding(self.results["endpoints"]["graphql"], {"url_or_path": path, "found_in": source_name, "line": ln})

        for m in self.BASEURL_RE.finditer(text):
            val = m.group(2)
            ln = line_number_from_index(text, m.start())
            self.add_finding(self.results["endpoints"]["base_urls"], {"value": val, "found_in": source_name, "line": ln})

        for m in self.FIREBASE_HINT_RE.finditer(text):
            with self._results_lock:
                self.results["firebase"]["detected"] = True
            ln = line_number_from_index(text, m.start())
            self.add_finding(self.results["firebase"]["hints"], {"match": m.group(0), "found_in": source_name, "line": ln})

        if self.results["firebase"]["detected"]:
            seen_blobs: set = set()

            def _try_add_firebase_blob(blob: str, ln: int):
                blob = blob.strip()
                sig = blob[:120]
                if sig in seen_blobs:
                    return
                seen_blobs.add(sig)
                parsed = self._parse_firebase_config(blob)
                # Only store if we got at least apiKey (real value) or authDomain
                if not parsed.get("apiKey") and not parsed.get("authDomain"):
                    return
                self.add_finding(self.results["firebase"]["configs"], {"blob": blob, "found_in": source_name, "line": ln})
                if parsed:
                    self.add_finding(self.results["firebase"]["configs_parsed"], {"fields": parsed, "found_in": source_name, "line": ln})

            for m in self.FIREBASE_STRICT_RE.finditer(text):
                _try_add_firebase_blob(m.group(1), line_number_from_index(text, m.start()))

            # Fallback: any object with a real Firebase API key (AIzaSy...)
            for m in self.FIREBASE_APIKEY_RE.finditer(text):
                _try_add_firebase_blob(m.group(1), line_number_from_index(text, m.start()))

        if "collection(" in text or "collectionGroup(" in text:
            with self._results_lock:
                self.results["firebase"]["detected"] = True
            for m in self.FIRESTORE_COLLECTION_CALL_RE.finditer(text):
                col = m.group(1)
                ln = line_number_from_index(text, m.start())
                self.add_finding(self.results["firebase"]["collections_probable"], {"name": col, "found_in": source_name, "line": ln, "evidence": "collection('...')"})
            for m in self.FIRESTORE_COLLECTIONGROUP_CALL_RE.finditer(text):
                col = m.group(1)
                ln = line_number_from_index(text, m.start())
                self.add_finding(self.results["firebase"]["collections_probable"], {"name": col, "found_in": source_name, "line": ln, "evidence": "collectionGroup('...')"})

        for m in self.COGNITO_RE.finditer(text):
            hit = m.group(1)
            ln = line_number_from_index(text, m.start())
            self.add_finding(self.results["exposed_configs"]["aws_amplify_cognito"], {"hit": hit, "found_in": source_name, "line": ln})

        for m in self.APPSYNC_RE.finditer(text):
            hit = m.group(1)
            ln = line_number_from_index(text, m.start())
            self.add_finding(self.results["exposed_configs"]["aws_appsync_amplify"], {"hit": hit, "found_in": source_name, "line": ln})

        for m in self.SENTRY_RE.finditer(text):
            dsn = m.group(0)
            ln = line_number_from_index(text, m.start())
            self.add_finding(self.results["exposed_configs"]["sentry"], {"dsn": dsn, "found_in": source_name, "line": ln})

        for m in self.GA_RE.finditer(text):
            gid = m.group(0)
            ln = line_number_from_index(text, m.start())
            self.add_finding(self.results["exposed_configs"]["google_analytics"], {"id": gid, "found_in": source_name, "line": ln})

        for m in self.SEGMENT_RE.finditer(text):
            key = m.group(1)
            ln = line_number_from_index(text, m.start())
            self.add_finding(self.results["exposed_configs"]["segment"], {"key": key, "found_in": source_name, "line": ln})

        if source_kind in ("js", "css"):
            for m in self.ROUTE_RE.finditer(text):
                p = m.group(1)
                if not self.looks_like_real_route(p):
                    continue
                ln = line_number_from_index(text, m.start())
                full = urljoin(base, p)
                self.add_finding(self.results["inventory"]["routes_full_urls"], {"path": p, "full_url": full, "found_in": source_name, "line": ln})

        for m in self.FIRESTORE_REST_RE.finditer(text):
            u = m.group(0)
            pm = self.FIRESTORE_DOCS_PATH_RE.search(u)
            if pm:
                rest_path = pm.group(1)
                col = rest_path.split("/")[0] if rest_path else ""
                if col:
                    self.add_finding(self.results["firebase"]["collections_probable"], {
                        "name": col,
                        "found_in": source_name,
                        "line": line_number_from_index(text, m.start()),
                        "evidence": "firestore REST URL"
                    })

        for m in self.RTDB_RE.finditer(text):
            project = m.group(1)
            path = m.group(2)
            seg = path.split("/")[0] if path else ""
            if seg:
                self.add_finding(self.results["firebase"]["collections_probable"], {
                    "name": seg,
                    "found_in": source_name,
                    "line": line_number_from_index(text, m.start()),
                    "evidence": f"rtdb {project}.firebaseio.com"
                })

        # Third-party service detection
        if source_kind in ("js", "html"):
            self._detect_third_party(text, source_name)

    # -----------------------------
    # Sourcemaps
    # -----------------------------
    def try_fetch_sourcemap(self, asset_url: str, asset_text: str, base_origin_url: str):
        m = self.SOURCEMAP_RE.search(asset_text or "")
        if not m:
            return
        map_ref = m.group(1).strip().strip('"').strip("'")
        map_url = urljoin(asset_url, map_ref)
        if not same_origin(map_url, base_origin_url):
            return

        with self._maps_lock:
            self.results["stats"]["maps_found"] += 1
            if self.results["stats"]["maps_fetched"] >= self.max_map_files:
                return

        fr = self.fetch(map_url)
        if self.sleep_between:
            time.sleep(self.sleep_between)
        if not fr or fr.status >= 400 or not fr.text:
            return
        try:
            data = json.loads(fr.text)
        except Exception:
            return

        with self._maps_lock:
            if self.results["stats"]["maps_fetched"] >= self.max_map_files:
                return
            self.results["stats"]["maps_fetched"] += 1

        with self._results_lock:
            self.results["exposed_configs"]["other"].append({
                "sourcemap": {
                    "map_url": map_url,
                    "file": data.get("file"),
                    "sources_sample": cap_list((data.get("sources") or []), 40),
                    "names_sample": cap_list((data.get("names") or []), 50),
                }
            })

        for i, sc in enumerate(cap_list((data.get("sourcesContent") or []), 12)):
            if isinstance(sc, str) and sc:
                self.extract_from_text(sc, base_origin_url, f"SOURCEMAP sourcesContent[{i}] @ {map_url}", source_kind="js")

    # -----------------------------
    # Screenshot (Playwright)
    # -----------------------------
    def take_screenshot(self, url: str, out_path: str) -> Optional[str]:
        if not self.enable_screenshot:
            return None
        try:
            from playwright.sync_api import sync_playwright  # type: ignore
        except Exception:
            with self._results_lock:
                self.results["notes"].append("Playwright no instalado: sin screenshots.")
            return None

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(viewport={"width": 1366, "height": 768})
                if self.extra_headers:
                    context.set_extra_http_headers(self.extra_headers)
                page = context.new_page()
                page.goto(url, timeout=45000, wait_until="domcontentloaded")
                try:
                    page.wait_for_load_state("networkidle", timeout=12000)
                except Exception:
                    pass
                page.screenshot(path=out_path, full_page=True)
                browser.close()
            return out_path
        except Exception as e:
            with self._results_lock:
                self.results["notes"].append(f"Screenshot error for {url}: {e}")
            return None

    # -----------------------------
    # Saving route bodies
    # -----------------------------
    def save_route_body(self, url: str, fr: FetchResult, prefix: str = "route") -> Optional[str]:
        if not self.save_route_bodies:
            return None
        if not fr.text or not is_probably_text(fr.content_type):
            return None

        p = urlparse(url)
        label = safe_filename(p.path.strip("/").replace("/", "_") or "root")
        fname = f"{prefix}__{label}__{sha1(url)}.txt"
        out_path = os.path.join(self.out_dir, "routes", fname)
        try:
            with open(out_path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(f"URL: {url}\n")
                f.write(f"Final: {fr.url}\n")
                f.write(f"Status: {fr.status}\n")
                f.write(f"Content-Type: {fr.content_type}\n")
                f.write(f"Elapsed(ms): {fr.elapsed_ms}\n")
                f.write("\n--- Headers (selected) ---\n")
                f.write(json.dumps(summarize_headers(fr.headers), ensure_ascii=False, indent=2))
                f.write("\n\n--- Body (truncated 250k) ---\n")
                f.write(fr.text[:250_000])
            return os.path.join("routes", fname)
        except Exception as e:
            with self._results_lock:
                self.results["notes"].append(f"Save body error {url}: {e}")
            return None

    # -----------------------------
    # Deep endpoints: analyze page scripts (threaded)
    # -----------------------------
    def _deep_analyze_page_scripts(self, html: str, page_url: str, base_origin: str):
        """
        From a page HTML, fetch and analyze same-origin scripts (limited) to extract endpoints.
        Runs script fetches in parallel.
        """
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return

        scripts = []
        for s in soup.find_all("script", src=True):
            src = s.get("src") or ""
            if not src:
                continue
            u = urljoin(page_url, src)
            if not same_origin(u, base_origin):
                continue
            scripts.append(u)

        scripts = uniq_list(scripts)[:25]  # hard cap
        if not scripts:
            return

        def worker(u: str):
            if self.verbose:
                print(f"{Fore.CYAN}[deep-js] {u}")
            ar = self.fetch(u)
            if self.sleep_between:
                time.sleep(self.sleep_between)
            if not ar or ar.status >= 400 or not ar.text:
                return
            self.extract_from_text(ar.text, base_origin, f"DEEP_ASSET: {u} (from {page_url})", source_kind="js")
            self.try_fetch_sourcemap(u, ar.text, base_origin)

        with ThreadPoolExecutor(max_workers=self.deep_threads) as ex:
            futs = [ex.submit(worker, u) for u in scripts]
            for _ in as_completed(futs):
                if self._stop_event.is_set():
                    break

    # -----------------------------
    # Crawl logic (threaded)
    # -----------------------------
    def _extract_title(self, html: str) -> str:
        try:
            soup = BeautifulSoup(html, "html.parser")
            t = soup.title.string.strip() if soup.title and soup.title.string else ""
            return t[:120]
        except Exception:
            return ""

    def crawl_pages_same_origin(self, start_url: str):
        if not self.crawl_pages:
            return

        print(f"[*] Crawling páginas (same-origin) [THREADS={self.crawl_threads}] con headers={'SI' if bool(self.extra_headers) else 'NO'} ...")
        base = start_url

        qwork: "queue.Queue[Tuple[str,int]]" = queue.Queue()
        qwork.put((start_url, 0))

        # v4.5: Seed from sitemap/robots discoveries
        sitemap_seeds = getattr(self, '_sitemap_seeds', set())
        for seed_url in sitemap_seeds:
            if same_origin(seed_url, base):
                qwork.put((seed_url, 1))  # depth 1 (already 1 hop from root)

        seen: Set[str] = set()
        seen_lock = threading.Lock()

        visited_count = 0
        visited_lock = threading.Lock()

        def can_take_page() -> bool:
            nonlocal visited_count
            with visited_lock:
                return visited_count < self.max_pages

        def mark_page_taken():
            nonlocal visited_count
            with visited_lock:
                visited_count += 1
                with self._stats_lock:
                    self.results["stats"]["pages_visited"] = visited_count

        def worker():
            while not self._stop_event.is_set():
                try:
                    url, depth = qwork.get(timeout=0.25)
                except queue.Empty:
                    return

                url = normalize_url(url)
                with seen_lock:
                    if url in seen:
                        qwork.task_done()
                        continue
                    seen.add(url)

                if not same_origin(url, base) or depth > self.max_depth:
                    qwork.task_done()
                    continue

                if not can_take_page():
                    qwork.task_done()
                    return

                print(f"{Fore.BLUE}[*] CRAWL visit: {url} (depth={depth})")
                fr = self.fetch(url)
                if self.sleep_between:
                    time.sleep(self.sleep_between)

                if not fr:
                    with self._results_lock:
                        self.results["crawl"]["access_matrix"].append({"url": url, "status": None, "ct": None, "ok": False, "reason": "fetch_failed"})
                    qwork.task_done()
                    continue

                ok = (fr.status < 400)
                with self._results_lock:
                    self.results["crawl"]["access_matrix"].append({
                        "url": url,
                        "status": fr.status,
                        "ct": fr.content_type,
                        "ok": ok,
                        "reason": "" if ok else f"HTTP_{fr.status}",
                    })

                title = self._extract_title(fr.text) if "html" in (fr.content_type or "") else ""
                saved_body = self.save_route_body(url, fr, prefix="crawl")

                shot_rel = None
                if self.enable_screenshot:
                    shot_name = f"crawl__{sha1(url)}.png"
                    shot_path = os.path.join(self.out_dir, "screens", shot_name)
                    if self.take_screenshot(url, shot_path):
                        shot_rel = os.path.join("screens", shot_name)
                        with self._screens_lock:
                            self.results["screenshots"]["routes"].append({"url": url, "path": shot_rel, "kind": "crawl"})

                with self._results_lock:
                    self.results["crawl"]["visited_pages"].append({
                        "url": url,
                        "final_url": fr.url,
                        "depth": depth,
                        "status": fr.status,
                        "ct": fr.content_type,
                        "title": title,
                        "screenshot": shot_rel,
                        "saved_body": saved_body,
                    })

                mark_page_taken()

                if "html" in (fr.content_type or "") and fr.text:
                    # v4.4: detect directory listings during crawl
                    if self._check_directory_listing(fr.text):
                        dl_entry = {"path": urlparse(url).path, "url": url, "status": fr.status,
                                    "ct": fr.content_type, "size": len(fr.text), "dir_listing": True,
                                    "redirect_to": None, "elapsed_ms": fr.elapsed_ms, "source": "crawl"}
                        with self._results_lock:
                            self.results["fuzzing"]["dir_listings"].append(dl_entry)
                        print(f"{Fore.RED}[!] DIR LISTING detectado (crawl): {url}")
                    try:
                        soup = BeautifulSoup(fr.text, "html.parser")
                    except Exception:
                        soup = None

                    if soup is not None:
                        self.extract_routes_from_dom(soup, base, page_url=url)
                        if self.ai_js_extract:
                            self._queue_ai_js_urls_from_html(fr.text, url, base)

                        for a in soup.find_all("a", href=True):
                            href = a.get("href") or ""
                            if not href or href.lower().startswith(("mailto:", "tel:", "javascript:", "data:")):
                                continue
                            u2 = urljoin(fr.url, href)
                            if not same_origin(u2, base):
                                continue
                            if self.ASSET_EXT_RE.match(u2):
                                continue
                            u2 = normalize_url(u2)
                            with seen_lock:
                                if u2 not in seen and depth + 1 <= self.max_depth:
                                    qwork.put((u2, depth + 1))

                        # v4.5: Follow prefetch/preload links for SPA pages
                        for link in soup.find_all("link", href=True):
                            rel = " ".join(link.get("rel", [])).lower()
                            if not any(r in rel for r in ["prefetch", "preload", "canonical", "alternate"]):
                                continue
                            href2 = link.get("href") or ""
                            if not href2:
                                continue
                            u3 = urljoin(fr.url, href2)
                            if not same_origin(u3, base) or self.ASSET_EXT_RE.match(u3):
                                continue
                            path3 = urlparse(u3).path or "/"
                            if self.looks_like_real_route(path3):
                                u3 = normalize_url(u3)
                                with seen_lock:
                                    if u3 not in seen and depth + 1 <= self.max_depth:
                                        qwork.put((u3, depth + 1))

                        # v4.5: Extract canonical / og:url as route hints
                        for meta in soup.find_all("meta"):
                            if meta.get("property", "").lower() == "og:url":
                                og_u = meta.get("content", "")
                                if og_u and same_origin(og_u, base):
                                    p_og = urlparse(og_u).path or "/"
                                    if self.looks_like_real_route(p_og):
                                        self.add_finding(self.results["inventory"]["routes_full_urls"], {
                                            "path": p_og,
                                            "full_url": normalize_url(og_u),
                                            "found_in": f"og:url @ {url}",
                                            "line": None,
                                        })

                    self.extract_from_text(fr.text, base, f"CRAWL_HTML: {url}", source_kind="html")

                    if self.deep_endpoints:
                        self._deep_analyze_page_scripts(fr.text, page_url=url, base_origin=base)
                else:
                    if is_probably_text(fr.content_type) and fr.text:
                        self.extract_from_text(fr.text, base, f"CRAWL_TEXT: {url}", source_kind="js" if "javascript" in (fr.content_type or "") else "html")

                qwork.task_done()

        threads = []
        for _ in range(self.crawl_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)

        # Wait until queue finishes or stop
        try:
            while any(t.is_alive() for t in threads):
                if self._stop_event.is_set():
                    break
                time.sleep(0.1)
        except KeyboardInterrupt:
            self._stop_event.set()

        # Drain quickly
        while not qwork.empty():
            try:
                qwork.get_nowait()
                qwork.task_done()
            except Exception:
                break

    # ----------------------------
    # v4.5: Sitemap & Robots probe
    # ----------------------------
    def _probe_sitemap_and_robots(self, base_origin: str, crawl_queue: Optional["queue.Queue"] = None) -> set:
        """Fetch /sitemap.xml, /sitemap_index.xml, /robots.txt and extract URLs.
        Returns a set of discovered URLs to seed into the spider queue."""
        if not self.probe_sitemap:
            return set()

        discovered: set = set()
        print(f"{Fore.CYAN}[v4.5] Probando sitemap.xml y robots.txt para semillas adicionales...")

        # --- robots.txt ---
        robots_url = urljoin(base_origin, "/robots.txt")
        fr = self.fetch(robots_url)
        if fr and fr.status == 200 and fr.text:
            for line in fr.text.splitlines():
                line = line.strip()
                if line.lower().startswith("sitemap:"):
                    sm = line.split(":", 1)[1].strip()
                    if sm.startswith("http"):
                        discovered.update(self._parse_sitemap_url(sm, base_origin))
                elif line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/" and not path.startswith("//*"):
                        u = urljoin(base_origin, path.split("*")[0])
                        if same_origin(u, base_origin) and not self.ASSET_EXT_RE.match(u):
                            discovered.add(normalize_url(u))

        # --- sitemap.xml ---
        for sm_path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml",
                        "/sitemap/sitemap.xml", "/news-sitemap.xml"]:
            sm_url = urljoin(base_origin, sm_path)
            discovered.update(self._parse_sitemap_url(sm_url, base_origin))

        # --- Next.js routes manifest ---
        build_id = self.results.get("nextjs", {}).get("buildId")
        if build_id:
            for manifest_path in [
                f"/_next/static/{build_id}/routes-manifest.json",
                f"/_next/static/{build_id}/_buildManifest.js",
            ]:
                mfr = self.fetch(urljoin(base_origin, manifest_path))
                if mfr and mfr.status == 200 and mfr.text:
                    # Extract paths from routes-manifest.json
                    try:
                        mdata = json.loads(mfr.text)
                        for section in ["dynamicRoutes", "staticRoutes", "dataRoutes"]:
                            for entry in (mdata.get(section) or []):
                                pg = entry.get("page") or entry.get("regex") or ""
                                if pg.startswith("/") and "{" not in pg:
                                    discovered.add(normalize_url(urljoin(base_origin, pg)))
                    except Exception:
                        # _buildManifest.js: extract page paths
                        for m in re.finditer(r'["\'](\/[a-zA-Z0-9/_:\[\]-]{1,120})["\']', mfr.text):
                            pg = m.group(1)
                            if "." not in pg.split("/")[-1]:  # not a file
                                discovered.add(normalize_url(urljoin(base_origin, pg)))

        if discovered:
            print(f"{Fore.GREEN}[v4.5] Sitemap/robots/manifests: {len(discovered)} URLs descubiertas como semillas")
        return discovered

    def _parse_sitemap_url(self, sitemap_url: str, base_origin: str) -> set:
        """Fetch a sitemap XML and extract all <loc> URLs. Handles sitemap indexes."""
        found: set = set()
        try:
            fr = self.fetch(sitemap_url)
            if not fr or fr.status != 200 or not fr.text:
                return found
            text = fr.text
            # Extract <loc> tags (works for both sitemap indexes and regular sitemaps)
            locs = re.findall(r'<loc>\s*(https?://[^\s<]+)\s*</loc>', text, re.IGNORECASE)
            for loc in locs:
                loc = loc.strip()
                if same_origin(loc, base_origin) and not self.ASSET_EXT_RE.match(loc):
                    found.add(normalize_url(loc))
                elif loc.endswith(".xml") and same_origin(loc, base_origin):
                    # It's a sub-sitemap index — recurse once
                    found.update(self._parse_sitemap_url(loc, base_origin))
        except Exception:
            pass
        return found

    # ----------------------------
    # v4.5: SPA route extraction from JS
    # ----------------------------
    def _extract_spa_routes_from_js(self, text: str, base: str, source_name: str):
        """Extract frontend routes declared in JS routers (React, Vue, Angular)."""
        seen: set = set()
        added = 0

        def _add_route(raw: str, kind: str):
            nonlocal added
            path = self._normalize_route_to_path(raw)
            if not path:
                return
            # Skip pure wildcard/param-only paths
            if path in ("/", "/*", "/:id", "/:slug") and raw.count("/") <= 1:
                return
            if not self.looks_like_real_route(path):
                if ":" in path or "[" in path:
                    # Keep param routes but normalize them
                    path = re.sub(r':[a-zA-Z_][a-zA-Z0-9_]*', ':param', path)
                    path = re.sub(r'\[[^\]]+\]', '[param]', path)
                else:
                    return
            if path in seen:
                return
            seen.add(path)
            added += 1
            full = urljoin(base, path)
            self.add_finding(self.results["endpoints"]["spa_routes"], {
                "path": path,
                "full_url": full,
                "router_type": kind,
                "found_in": source_name,
            })
            # Also add to inventory routes
            self.add_finding(self.results["inventory"]["routes_full_urls"], {
                "path": path,
                "full_url": full,
                "found_in": f"SPA-ROUTER ({kind}): {source_name}",
                "line": None,
                "route_type": "frontend",
            })

        # React Router JSX / object syntax
        for m in self.REACT_ROUTER_JSX_RE.finditer(text):
            _add_route(m.group(1), "react-router")

        # Vue Router
        for m in self.VUE_ROUTER_PATH_RE.finditer(text):
            _add_route(m.group(1), "vue-router")

        # Angular Router
        for m in self.ANGULAR_ROUTER_PATH_RE.finditer(text):
            raw = m.group(1)
            if raw:  # Angular paths are relative (no leading /)
                _add_route("/" + raw.lstrip("/"), "angular-router")

        # Generic SPA route map object
        for m in self.SPA_ROUTE_OBJECT_RE.finditer(text):
            _add_route(m.group(1), "spa-map")

        if added and self.verbose:
            print(f"{Fore.CYAN}[spa-routes] {added} rutas SPA extraídas de {source_name[:80]}")

    # ----------------------------
    # v4.5: API call confidence scoring
    # ----------------------------
    def _score_api_call_probability(self, url: str, context: str) -> int:
        """Score 0-100: how likely is this URL actually consumed as an API call."""
        score = 0
        ctx = (context or "").lower()
        url_lower = (url or "").lower()

        # Strong positive signals
        if re.search(r'\bfetch\s*\(', ctx):
            score += 40
        if re.search(r'\baxios\s*[.(]', ctx):
            score += 40
        if re.search(r'\b(usequery|usemutation|useinfinitequery|useswr|queryFn|mutationFn)\b', ctx):
            score += 35
        if re.search(r'\b(await|then|promise|async)\b', ctx):
            score += 15
        if re.search(r'(authorization|bearer|token|api.?key|x-api-key)', ctx):
            score += 20
        if re.search(r'\b(method\s*:|method\s*=)', ctx):
            score += 15
        if re.search(r'\b(headers\s*:|content.type|application/json)', ctx):
            score += 12
        if re.search(r'\b(body\s*:|json\.stringify|formdata)', ctx):
            score += 12

        # URL structure signals
        if re.search(r'/(api|v\d+|graphql|rest|auth|oauth|services|endpoint)/', url_lower):
            score += 20
        if re.search(r'[{:][a-z_]+[}/]|\[id\]', url_lower):
            score += 10  # has path params
        if url_lower.startswith('http'):
            score += 8
        elif url_lower.startswith('/'):
            score += 5

        # Negative signals
        if re.search(r'(?:^|\s)//.*(?:https?://|/[a-z])', ctx):
            score -= 30  # looks like a comment
        if re.search(r'\bconsole\.(log|error|warn|info)\b', ctx):
            score -= 25
        if re.search(r'\b(href|src|link|url)\s*=\s*["\']', ctx):
            score -= 15  # href/src assignment, probably DOM
        if re.search(r'\bdocument\.write|innerHTML\s*=|innerText\s*=', ctx):
            score -= 20
        if re.search(r'//\s*(https?://|example\.com|todo|fixme|note)', ctx, re.IGNORECASE):
            score -= 30  # definitely a comment
        if re.search(r'\.(jpg|png|gif|svg|css|html|ico)(["\'/]|$)', url_lower):
            score -= 40  # static asset

        return max(0, min(100, score))

    # ----------------------------
    # v4.5: TanStack Query / RTK Query  
    # ----------------------------
    def _extract_query_library_calls(self, text: str, base: str, source_name: str):
        """Extract API calls from TanStack Query, SWR, and RTK Query patterns."""

        # SWR: useSWR('/api/...', fetcher)
        for m in self.SWR_RE.finditer(text):
            url = m.group(1)
            if url.startswith('/') or url.startswith('http'):
                ln = line_number_from_index(text, m.start())
                full = urljoin(base, url) if url.startswith('/') else url
                start_ctx = max(0, m.start() - 100)
                end_ctx = min(len(text), m.end() + 100)
                ctx = text[start_ctx:end_ctx]
                confidence = self._score_api_call_probability(url, ctx)
                self.add_finding(self.results["endpoints"]["tanstack_query"], {
                    "type": "swr",
                    "method": "GET",
                    "url_or_path": url,
                    "full_url": full,
                    "confidence": confidence,
                    "found_in": source_name,
                    "line": ln,
                    "evidence": "useSWR(...)",
                })
                self.add_finding(self.results["endpoints"]["requests_inferred"], {
                    "method": "GET",
                    "url_or_path": url,
                    "full_url": full,
                    "params": extract_query_params(full),
                    "body_keys": [],
                    "body_hint": None,
                    "headers_hint": None,
                    "found_in": source_name,
                    "line": ln,
                    "evidence": "useSWR(...)",
                    "confidence": confidence,
                })

        # TanStack queryFn with fetch/axios
        for m in self.TANSTACK_QUERYFN_RE.finditer(text):
            url = m.group(1)
            if not url:
                continue
            ln = line_number_from_index(text, m.start())
            full = urljoin(base, url) if url.startswith('/') else url
            start_ctx = max(0, m.start() - 150)
            end_ctx = min(len(text), m.end() + 200)
            ctx = text[start_ctx:end_ctx]
            # Detect method from surrounding context
            meth = "GET"
            if re.search(r'builder\.mutation|useMutation', ctx, re.IGNORECASE):
                meth = "POST"
            confidence = self._score_api_call_probability(url, ctx) + 20  # bonus for being in queryFn
            confidence = min(100, confidence)
            self.add_finding(self.results["endpoints"]["tanstack_query"], {
                "type": "tanstack-queryFn",
                "method": meth,
                "url_or_path": url,
                "full_url": full,
                "confidence": confidence,
                "found_in": source_name,
                "line": ln,
                "evidence": "queryFn: () => fetch/axios(...)",
            })
            self.add_finding(self.results["endpoints"]["requests_inferred"], {
                "method": meth,
                "url_or_path": url,
                "full_url": full,
                "params": extract_query_params(full),
                "body_keys": [],
                "body_hint": None,
                "headers_hint": None,
                "found_in": source_name,
                "line": ln,
                "evidence": "queryFn: () => fetch/axios(...)",
                "confidence": confidence,
            })

        # RTK Query: baseUrl + endpoints
        rtk_base = None
        m_base = self.RTK_BASE_URL_RE.search(text)
        if m_base:
            rtk_base = m_base.group(1)
            ln_base = line_number_from_index(text, m_base.start())
            self.add_finding(self.results["endpoints"]["base_urls"], {
                "value": rtk_base,
                "found_in": f"RTK-createApi: {source_name}",
                "line": ln_base,
            })

        for m in self.RTK_ENDPOINT_RE.finditer(text):
            ep_path = m.group(1) or m.group(2) or ""
            if not ep_path:
                continue
            ln = line_number_from_index(text, m.start())
            meth = "POST" if "mutation" in text[max(0,m.start()-30):m.start()].lower() else "GET"
            # Combine with RTK base if available
            if rtk_base and not ep_path.startswith("http"):
                full = rtk_base.rstrip("/") + "/" + ep_path.lstrip("/")
            elif ep_path.startswith("/"):
                full = urljoin(base, ep_path)
            else:
                full = ep_path
            ctx = text[max(0, m.start()-100):min(len(text), m.end()+100)]
            confidence = self._score_api_call_probability(ep_path, ctx) + 25  # builder.query bonus
            confidence = min(100, confidence)
            self.add_finding(self.results["endpoints"]["rtk_endpoints"], {
                "method": meth,
                "url_or_path": ep_path,
                "full_url": full,
                "base_url": rtk_base,
                "confidence": confidence,
                "found_in": source_name,
                "line": ln,
                "evidence": f"builder.{'mutation' if meth == 'POST' else 'query'}(...)",
            })
            self.add_finding(self.results["endpoints"]["requests_inferred"], {
                "method": meth,
                "url_or_path": ep_path,
                "full_url": full,
                "params": extract_query_params(full),
                "body_keys": [],
                "body_hint": None,
                "headers_hint": None,
                "found_in": source_name,
                "line": ln,
                "evidence": f"RTK builder.{'mutation' if meth == 'POST' else 'query'}(...)",
                "confidence": confidence,
            })

    # ----------------------------
    # v4.5: GraphQL operations
    # ----------------------------
    def _extract_graphql_operations(self, text: str, source_name: str):
        """Extract GraphQL operation names and types from gql template literals."""
        # gql`query/mutation OpName { ... }`
        for m in self.GQL_OPERATION_RE.finditer(text):
            op_type = m.group(1).lower()
            op_name = m.group(2)
            ln = line_number_from_index(text, m.start())
            self.add_finding(self.results["endpoints"]["graphql_operations"], {
                "type": op_type,
                "name": op_name,
                "found_in": source_name,
                "line": ln,
            })

        # Inline { query: "query OpName ..." }
        for m in self.GQL_INLINE_RE.finditer(text):
            op_type = m.group(1).lower()
            op_name = m.group(2)
            ln = line_number_from_index(text, m.start())
            self.add_finding(self.results["endpoints"]["graphql_operations"], {
                "type": op_type,
                "name": op_name,
                "found_in": source_name,
                "line": ln,
            })

    # ----------------------------
    # v4.5: Base URL combinations
    # ----------------------------
    def _extract_base_url_combinations(self, text: str, base: str, source_name: str):
        """When BASE_URL vars are found alongside relative paths in same JS file,
        combine them to generate concrete absolute endpoint URLs."""
        # Collect all BASE_URL-like variable values from this text
        base_urls_in_file: List[str] = []
        for m in self.BASEURL_RE.finditer(text):
            val = m.group(2).rstrip("/")
            if val.startswith("http") and len(val) > 8:
                base_urls_in_file.append(val)

        if not base_urls_in_file:
            return

        # Find relative API paths in the same file
        rel_paths: set = set()
        for m in self.REL_ENDPOINT_RE.finditer(text):
            rel_paths.add(m.group(1))

        # Also find paths next to fetch/axios calls
        for m in self.AXIOS_SHORT_RE.finditer(text):
            p = m.group("url")
            if p.startswith("/"):
                rel_paths.add(p)

        for m in self.FETCH_CALL_RE.finditer(text):
            p = m.group("url")
            if p.startswith("/"):
                rel_paths.add(p)

        for base_url_val in base_urls_in_file:
            for path in sorted(rel_paths)[:50]:  # cap combinatorial explosion
                combined = base_url_val + path
                # Sanity check: the path should look like an endpoint
                if re.search(r'/[a-zA-Z]', path) and len(combined) < 250:
                    self.add_finding(self.results["endpoints"]["absolute"], {
                        "url": combined,
                        "params": extract_query_params(combined),
                        "found_in": f"BASE_URL+PATH_COMBO: {source_name}",
                        "line": None,
                        "confidence": 55,  # moderate: inferred combination
                    })

    # ----------------------------
    # v4.5: Build frontend map tree
    # ----------------------------
    def _build_frontend_map(self) -> dict:
        """Build a hierarchical map of frontend routes grouped by path segments."""
        with self._results_lock:
            routes = list(self.results.get("inventory", {}).get("routes_full_urls") or [])
            authz_items = list(self.results.get("authz_audit", {}).get("items") or [])

        # Build a status lookup from authz audit
        status_lookup: dict = {}
        for item in authz_items:
            p = item.get("path") or "/"
            status_lookup[p] = {
                "status": item.get("status"),
                "state": item.get("state"),
                "methods": item.get("methods") or ["GET"],
            }

        tree: dict = {}
        for route in routes:
            path = route.get("path") or "/"
            route_type = route.get("route_type") or self._classify_route_type(path)
            parts = [p for p in path.strip("/").split("/") if p]

            node = tree
            for part in parts:
                if part not in node:
                    node[part] = {"_children": {}, "_paths": []}
                node = node[part]["_children"]

            # Leaf info
            leaf_key = parts[-1] if parts else "[root]"
            authz = status_lookup.get(path, {})
            leaf_info = {
                "path": path,
                "route_type": route_type,
                "found_in": route.get("found_in", ""),
                "status": authz.get("status"),
                "state": authz.get("state"),
                "methods": authz.get("methods") or [],
            }

            # Store leaf info at correct level
            parent = tree
            for part in parts[:-1]:
                parent = parent.get(part, {}).get("_children", {})
            if leaf_key in parent:
                parent[leaf_key].setdefault("_paths", []).append(leaf_info)
            else:
                parent[leaf_key] = {"_children": {}, "_paths": [leaf_info]}

        return tree

    # -----------------------------
    # Main scan (root + assets) [assets threaded]
    # -----------------------------
    def scan_source_and_assets(self):
        print(f"[*] Analizando HTML inicial y assets (same-origin)...")
        fr = self.fetch(self.target_url)
        if not fr:
            print(f"{Fore.RED}[!] No pude acceder a la URL.")
            return

        # v4.5: Probe sitemap/robots early to seed the crawler
        self._sitemap_seeds: set = set()  # will be consumed by crawl

        with self._results_lock:
            self.results["final_url"] = fr.url
            self.results["server_headers"] = summarize_headers(fr.headers)

        base = fr.url
        self.fingerprint_html_and_headers(fr.text, fr.headers)

        soup = BeautifulSoup(fr.text, "html.parser")

        internal_links: Set[str] = set()
        for a in soup.find_all("a", href=True):
            u = urljoin(base, a["href"])
            if same_origin(u, base):
                internal_links.add(normalize_url(u))
        with self._results_lock:
            self.results["inventory"]["internal_links"] = sorted(internal_links)

        self.extract_routes_from_dom(soup, base, page_url=base)
        if self.ai_js_extract:
            self._prepare_ai_js_workspace()
            self._queue_ai_js_urls_from_html(fr.text, base, base)

        scripts = [urljoin(base, s["src"]) for s in soup.find_all("script", src=True)]
        styles = []
        for l in soup.find_all("link", href=True):
            rel = " ".join(l.get("rel", [])).lower()
            if "stylesheet" in rel:
                styles.append(urljoin(base, l["href"]))
        imgs = [urljoin(base, im["src"]) for im in soup.find_all("img", src=True)]

        next_data = soup.find("script", {"id": "__NEXT_DATA__"})
        if next_data and next_data.string:
            try:
                data = json.loads(next_data.string)
                with self._results_lock:
                    self.results["nextjs"]["buildId"] = data.get("buildId")
                    self.results["nextjs"]["page"] = data.get("page")
                    self.results["nextjs"]["detected"] = True
            except Exception:
                pass

        with self._results_lock:
            self.results["nextjs"]["assets"]["scripts"] = uniq_list(scripts)
            self.results["nextjs"]["assets"]["styles"] = uniq_list(styles)
            self.results["nextjs"]["assets"]["images"] = uniq_list(imgs)

            self.results["inventory"]["assets"]["scripts"] = self.results["nextjs"]["assets"]["scripts"]
            self.results["inventory"]["assets"]["styles"] = self.results["nextjs"]["assets"]["styles"]
            self.results["inventory"]["assets"]["images"] = self.results["nextjs"]["assets"]["images"]

        self.extract_from_text(fr.text, base, f"HTML: {base}", source_kind="html")

        # Threaded asset fetch
        asset_urls = uniq_list(scripts + styles)
        asset_urls = [u for u in asset_urls if same_origin(u, base)]
        asset_urls = asset_urls[: self.max_assets]

        print(f"{Fore.CYAN}[*] Assets queued: {len(asset_urls)} (THREADS={self.asset_threads})")

        def asset_worker(u: str):
            if self.verbose:
                print(f"{Fore.BLUE}[*] ASSET fetch: {u}")
            ar = self.fetch(u)
            if self.sleep_between:
                time.sleep(self.sleep_between)
            if not ar or ar.status >= 400:
                return
            with self._stats_lock:
                self.results["stats"]["assets_fetched"] += 1

            is_js = u.lower().endswith(".js") or "javascript" in (ar.content_type or "")
            kind = "js" if is_js else "css"
            self.extract_from_text(ar.text, base, f"ASSET: {u}", source_kind=kind)
            if is_js:
                self.try_fetch_sourcemap(u, ar.text, base)

        with ThreadPoolExecutor(max_workers=self.asset_threads) as ex:
            futs = [ex.submit(asset_worker, u) for u in asset_urls]
            for _ in as_completed(futs):
                if self._stop_event.is_set():
                    break

        # v4.5: Probe sitemap/robots AFTER we have buildId from __NEXT_DATA__
        self._sitemap_seeds = self._probe_sitemap_and_robots(base)

        # Crawl (threaded)
        self.crawl_pages_same_origin(base)

        # Main screenshot
        if self.enable_screenshot:
            main_shot = os.path.join(self.out_dir, "screenshot.png")
            if self.take_screenshot(self.target_url, main_shot):
                with self._results_lock:
                    self.results["screenshots"]["main"] = "screenshot.png"

        if self.probe_get_endpoints:
            self._probe_inferred_get_endpoints(base)

        if self.audit_authz:
            self._authz_audit_routes(base)

        # v4.4: New modules
        self._generate_google_dorks()

        if self.fuzz:
            self._fuzz_directories(base)

        if self.probe_firebase:
            self._probe_firebase_access(base)

        if self.ai_js_extract:
            self._download_all_ai_js_assets(base)
            self._run_post_crawl_ai_analysis()

        self._dedup_findings()

    def _probe_inferred_get_endpoints(self, base_origin: str):
        print("[*] Probing seguro (solo GET) de algunos endpoints inferidos... (threaded)")
        out = []
        candidates = []
        with self._results_lock:
            reqs = list(self.results["endpoints"]["requests_inferred"])

        for r in reqs:
            meth = (r.get("method") or "").upper()
            full = r.get("full_url") or ""
            if not full or not full.startswith("http"):
                continue
            if not same_origin(full, base_origin):
                continue
            if meth not in ("GET", "UNKNOWN"):
                continue
            if r.get("body_hint"):
                continue
            candidates.append(full)

        candidates = uniq_list(candidates)[:25]

        def worker(u: str):
            fr = self.fetch(u)
            if self.sleep_between:
                time.sleep(self.sleep_between)
            if not fr:
                return {"url": u, "status": None, "ct": None}
            return {"url": u, "status": fr.status, "ct": fr.content_type}

        with ThreadPoolExecutor(max_workers=min(10, self.threads)) as ex:
            futs = [ex.submit(worker, u) for u in candidates]
            for f in as_completed(futs):
                if self._stop_event.is_set():
                    break
                try:
                    out.append(f.result())
                except Exception:
                    pass

        with self._results_lock:
            self.results["endpoints"]["probed_get"] = out

    # -----------------------------
    # AuthZ audit (threaded)
    # -----------------------------
    def _build_route_candidates(self, base_origin: str) -> List[str]:
        candidates: Set[str] = set()

        with self._results_lock:
            inv_routes = list(self.results.get("inventory", {}).get("routes_full_urls") or [])
            inv_links = list(self.results.get("inventory", {}).get("internal_links") or [])
            rels = list(self.results.get("endpoints", {}).get("relative") or [])
            reqs = list(self.results.get("endpoints", {}).get("requests_inferred") or [])

        for r in inv_routes:
            u = r.get("full_url") or ""
            if u and same_origin(u, base_origin):
                candidates.add(normalize_url(u))

        for u in inv_links:
            if u and same_origin(u, base_origin):
                candidates.add(normalize_url(u))

        for r in rels:
            u = r.get("full_url") or ""
            if u and same_origin(u, base_origin):
                candidates.add(normalize_url(u))

        for r in reqs:
            u = r.get("full_url") or ""
            if u and u.startswith("http") and same_origin(u, base_origin):
                candidates.add(normalize_url(u))

        out = sorted(candidates)
        return out[: self.authz_max_routes]

    def _is_login_like(self, fr: FetchResult) -> bool:
        final_path = (urlparse(fr.url).path or "").lower()
        if "login" in final_path or "signin" in final_path:
            return True

        text = (fr.text or "")[:9000].lower()
        login_words = ["login", "iniciar sesión", "signin", "password", "contraseña", "autentic", "auth", "ingresar"]
        hits = sum(1 for w in login_words if w in text)
        return hits >= 2

    def _classify_access(self, fr: Optional[FetchResult], base_origin: str, req_url: str) -> Tuple[str, str]:
        if fr is None:
            return ("sin acceso", "fetch_failed")

        if fr.status in (401, 403):
            return ("sin acceso", f"http_{fr.status}")

        if not same_origin(fr.url, base_origin):
            return ("sin acceso", "redirect_other_origin")

        loc = (fr.headers.get("Location") or fr.headers.get("location") or "").lower()
        if fr.status in (301, 302, 303, 307, 308) and ("login" in loc or "signin" in loc):
            return ("sin acceso", f"redirect_login ({fr.status})")

        if fr.status < 400 and self._is_login_like(fr):
            return ("sin acceso", "login_like_content")

        if fr.status in (200, 204):
            return ("con acceso", f"http_{fr.status}")

        if fr.status == 404:
            return ("sin acceso", "not_found_404")

        if fr.status < 400:
            return ("con acceso", f"http_{fr.status}")
        return ("sin acceso", f"http_{fr.status}")

    def _params_body_map_by_path(self, base_origin: str) -> Dict[str, Dict[str, Any]]:
        m: Dict[str, Dict[str, Any]] = {}

        with self._results_lock:
            reqs = list(self.results.get("endpoints", {}).get("requests_inferred") or [])

        for r in reqs:
            full = r.get("full_url") or ""
            if not full or not full.startswith("http"):
                continue
            if not same_origin(full, base_origin):
                continue
            p = urlparse(full).path or "/"
            if p not in m:
                m[p] = {"params": set(), "body_keys": set(), "methods": set(), "samples": []}
            m[p]["methods"].add((r.get("method") or "UNKNOWN").upper())
            for qk in (r.get("params") or []):
                m[p]["params"].add(qk)
            for bk in (r.get("body_keys") or []):
                m[p]["body_keys"].add(bk)
            if len(m[p]["samples"]) < 5:
                m[p]["samples"].append({
                    "method": (r.get("method") or "UNKNOWN").upper(),
                    "evidence": r.get("evidence"),
                    "found_in": r.get("found_in"),
                    "line": r.get("line"),
                    "body_hint": r.get("body_hint"),
                })
        return m

    def _ai_summarize_route(self, route_url: str, fr: Optional[FetchResult], inferred: Dict[str, Any]) -> str:
        status = fr.status if fr else None
        ct = fr.content_type if fr else ""
        params = sorted(list(inferred.get("params") or []))
        body_keys = sorted(list(inferred.get("body_keys") or []))
        methods = sorted(list(inferred.get("methods") or []))

        heuristic = f"Ruta {urlparse(route_url).path} | status={status} ct={ct} | methods={methods or ['GET']} | params={params or []} | body_keys={body_keys or []}"

        if not self.ai_ollama:
            return heuristic

        try:
            import subprocess
            my_env = os.environ.copy()
            my_env["OLLAMA_HOST"] = getattr(self, "ollama_url", "http://localhost:11434")
            subprocess.run(["ollama", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, env=my_env)
        except Exception:
            return heuristic + " | (ollama no disponible)"

        snippet = ""
        if fr and fr.text:
            snippet = re.sub(r"\s+", " ", fr.text[:1500])
        prompt = (
            "Resume en 1-2 frases (ES) la ruta y qué parece ser. "
            "No inventes. Si es login/unauthorized dilo.\n\n"
            f"URL: {route_url}\n"
            f"Status: {status}\n"
            f"CT: {ct}\n"
            f"Methods inferred: {methods}\n"
            f"Query params inferred: {params}\n"
            f"Body keys inferred: {body_keys}\n"
            f"HTML/JSON snippet: {snippet}\n"
        )

        try:
            import subprocess
            my_env = os.environ.copy()
            my_env["OLLAMA_HOST"] = getattr(self, "ollama_url", "http://localhost:11434")
            cp = subprocess.run(
                ["ollama", "run", self.ai_model],
                input=prompt.encode("utf-8", errors="ignore"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=12,
                env=my_env
            )
            out = (cp.stdout.decode("utf-8", errors="ignore") or "").strip()
            if not out:
                return heuristic + " | (ollama vacío)"
            out = re.sub(r"\s+", " ", out).strip()
            return out[:340]
        except Exception as e:
            return heuristic + f" | (ollama error: {e})"

    def _authz_audit_routes(self, base_origin: str):
        print(f"[*] AuthZ audit (THREADS={self.authz_threads}): visitando rutas detectadas (max={self.authz_max_routes}) "
              f"screenshots={'SI' if self.authz_take_screenshots else 'NO'} ...")

        candidates = self._build_route_candidates(base_origin)
        inferred_map = self._params_body_map_by_path(base_origin)

        items_lock = threading.Lock()
        items: List[dict] = []

        def worker(u: str):
            if self._stop_event.is_set():
                return
            if self.verbose:
                print(f"{Fore.BLUE}[*] AUTHZ test: {u}")
            fr = self.fetch(u)
            if self.sleep_between:
                time.sleep(self.sleep_between)
            state, reason = self._classify_access(fr, base_origin, u)

            p = urlparse(u).path or "/"
            inferred = inferred_map.get(p, {"params": set(), "body_keys": set(), "methods": set(), "samples": []})

            params = sorted(list(inferred.get("params") or []))
            body_keys = sorted(list(inferred.get("body_keys") or []))
            methods = sorted(list(inferred.get("methods") or [])) or ["GET"]

            saved_body = None
            if fr:
                saved_body = self.save_route_body(u, fr, prefix="authz")

            shot_rel = None
            if self.enable_screenshot and self.authz_take_screenshots:
                shot_name = f"authz__{sha1(u)}.png"
                shot_path = os.path.join(self.out_dir, "screens", shot_name)
                if self.take_screenshot(u, shot_path):
                    shot_rel = os.path.join("screens", shot_name)
                    with self._screens_lock:
                        self.results["screenshots"]["routes"].append({"url": u, "path": shot_rel, "kind": "authz"})

            resp_snip = None
            if self.authz_show_response and fr and fr.text:
                resp_snip = re.sub(r"\s+", " ", fr.text[: self.authz_response_chars]).strip()

            if self.deep_endpoints and fr and "html" in (fr.content_type or "") and fr.text:
                self._deep_analyze_page_scripts(fr.text, page_url=u, base_origin=base_origin)

            ai_summary = self._ai_summarize_route(u, fr, inferred)

            with items_lock:
                items.append({
                    "url": u,
                    "path": p,
                    "status": fr.status if fr else None,
                    "final_url": fr.url if fr else None,
                    "ct": fr.content_type if fr else None,
                    "state": state,
                    "reason": reason,
                    "params": params,
                    "methods": methods,
                    "body_keys": body_keys,
                    "samples": inferred.get("samples") or [],
                    "screenshot": shot_rel,
                    "saved_body": saved_body,
                    "response_snippet": resp_snip,
                    "ai_summary": ai_summary,
                })

            with self._stats_lock:
                self.results["stats"]["authz_routes_tested"] += 1

        with ThreadPoolExecutor(max_workers=self.authz_threads) as ex:
            futs = [ex.submit(worker, u) for u in candidates]
            for _ in as_completed(futs):
                if self._stop_event.is_set():
                    break

        with self._results_lock:
            self.results["authz_audit"]["items"] = items

    # -----------------------------
    # v4.4: Directory listing check
    # -----------------------------
    def _check_directory_listing(self, html: str) -> bool:
        """Check if HTML response indicates an open directory listing."""
        if not html:
            return False
        snippet = html[:8000]
        for rx in self.DIRLIST_INDICATORS:
            if rx.search(snippet):
                return True
        return False

    # -----------------------------
    # v4.4: Directory fuzzing
    # -----------------------------
    def _fuzz_directories(self, base_origin: str):
        """Fuzz common directories/files against the target. Threaded."""
        if not self.fuzz:
            return

        print(f"{Fore.CYAN}[*] Fuzzing directorios [THREADS={self.fuzz_thread_count}] ...")

        # Build wordlist
        paths = list(self.DEFAULT_FUZZ_PATHS)
        if self.fuzz_wordlist_file:
            try:
                with open(self.fuzz_wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            if not line.startswith("/"):
                                line = "/" + line
                            paths.append(line)
                print(f"{Fore.CYAN}[*] Wordlist cargada: {self.fuzz_wordlist_file} (+{len(paths) - len(self.DEFAULT_FUZZ_PATHS)} paths)")
            except Exception as e:
                with self._results_lock:
                    self.results["notes"].append(f"Fuzz wordlist error: {e}")

        paths = uniq_list(paths)[: self.fuzz_max]

        fuzz_found_lock = threading.Lock()
        fuzz_found: List[dict] = []
        dir_listings: List[dict] = []
        tested = [0]
        tested_lock = threading.Lock()

        def fuzz_worker(path: str):
            if self._stop_event.is_set():
                return
            url = urljoin(base_origin, path)
            fr = self.fetch(url)
            if self.sleep_between:
                time.sleep(self.sleep_between)

            with tested_lock:
                tested[0] += 1

            if not fr:
                return

            # Skip 404
            if fr.status == 404:
                return

            is_dir_listing = False
            if fr.status < 400 and "html" in (fr.content_type or ""):
                is_dir_listing = self._check_directory_listing(fr.text)

            redirect_to = None
            if fr.status in (301, 302, 303, 307, 308):
                redirect_to = fr.headers.get("Location") or fr.headers.get("location")

            size = len(fr.text) if fr.text else 0

            entry = {
                "path": path,
                "url": url,
                "status": fr.status,
                "ct": fr.content_type,
                "size": size,
                "dir_listing": is_dir_listing,
                "redirect_to": redirect_to,
                "elapsed_ms": fr.elapsed_ms,
            }

            with fuzz_found_lock:
                fuzz_found.append(entry)
                if is_dir_listing:
                    dir_listings.append(entry)

            if self.verbose:
                tag = f" [DIR LISTING!]" if is_dir_listing else ""
                redir_tag = f" -> {redirect_to}" if redirect_to else ""
                print(f"{Fore.GREEN}[FUZZ] {fr.status} {path} ({size}b){tag}{redir_tag}")

        with ThreadPoolExecutor(max_workers=self.fuzz_thread_count) as ex:
            futs = [ex.submit(fuzz_worker, p) for p in paths]
            for _ in as_completed(futs):
                if self._stop_event.is_set():
                    break

        # Sort by status code for readability
        fuzz_found.sort(key=lambda x: (x["status"], x["path"]))

        with self._results_lock:
            self.results["fuzzing"]["found"] = fuzz_found
            self.results["fuzzing"]["dir_listings"] = dir_listings
            self.results["fuzzing"]["paths_tested"] = tested[0]
        with self._stats_lock:
            self.results["stats"]["fuzz_paths_tested"] = tested[0]
            self.results["stats"]["fuzz_found"] = len(fuzz_found)

        # Summary
        by_status = {}
        for e in fuzz_found:
            s = e["status"]
            by_status[s] = by_status.get(s, 0) + 1
        status_summary = " · ".join(f"{s}={c}" for s, c in sorted(by_status.items()))
        print(f"{Fore.GREEN}[+] Fuzzing completado: {tested[0]} paths → {len(fuzz_found)} encontrados ({status_summary})")
        if dir_listings:
            print(f"{Fore.RED}[!] {len(dir_listings)} DIRECTORY LISTING(s) detectados!")
            for dl in dir_listings:
                print(f"{Fore.RED}    → {dl['path']}")

    # -----------------------------
    # v4.4: Google dorks generation
    # -----------------------------
    def _generate_google_dorks(self):
        """Generate Google dork queries for the target domain (passive, no network)."""
        if not self.google_dorks:
            return

        try:
            domain = urlparse(self.target_url).netloc
            if not domain:
                return
        except Exception:
            return

        print(f"{Fore.CYAN}[*] Ejecutando Google dorks para {domain} de forma automatizada (podría demorar)...")

        queries = []
        consecutive_blocks = 0
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
        }
        cookies = {
            "CONSENT": "YES+cb.20230101-14-p0.es+FX+999"  # Bypass cookie consent screen
        }
        
        for tmpl in self.GOOGLE_DORK_TEMPLATES:
            dork = tmpl["tpl"].replace("{domain}", domain)
            google_url = f"https://www.google.com/search?q={requests.utils.quote(dork)}"
            
            found = None
            try:
                # Retardo para evitar baneos de Google
                time.sleep(2.0)
                res = requests.get(google_url, headers=headers, cookies=cookies, timeout=10)
                
                if res.status_code == 200:
                    html_lower = res.text.lower()
                    
                    # 1. Comprobar si caímos en la página de consentimiento o en un soft-ban (ej. CAPTCHA con 200 OK)
                    if "consent.google.com" in html_lower or \
                       "antes de ir a google" in html_lower or \
                       "before you continue" in html_lower or \
                       'id="captcha"' in html_lower or \
                       "recaptcha" in html_lower:
                        found = "blocked"  # Captcha / soft-ban
                    
                    # 2. Comprobar si no hay resultados
                    elif "did not match any documents" in html_lower or \
                         "no se han encontrado resultados" in html_lower or \
                         "no documents match" in html_lower or \
                         "no results found" in html_lower or \
                         "no match for" in html_lower or \
                         "no produjo ningún documento" in html_lower:
                        found = False
                        
                    # 3. Solo si pasó lo anterior, asumimos que encontró algo útil
                    else:
                        found = True
                        
                elif res.status_code == 429:
                    print(f"{Fore.YELLOW}[!] Google devolvió 429 (Too Many Requests). IP bloqueada temporalmente.")
                    found = "blocked"
                else:
                    found = None
            except Exception:
                found = None

            if found == "blocked":
                consecutive_blocks += 1
            else:
                consecutive_blocks = 0

            queries.append({
                "category": tmpl["cat"],
                "dork": dork,
                "description": tmpl["desc"],
                "google_url": google_url,
                "found": found
            })

            if consecutive_blocks >= 3:
                print(f"{Fore.RED}[!] 3 bloqueos consecutivos de Google — deteniendo búsqueda de dorks. Solo se mostrarán URLs en el reporte.")
                # Mark remaining as blocked-skipped
                for remaining_tmpl in self.GOOGLE_DORK_TEMPLATES[len(queries):]:
                    remaining_dork = remaining_tmpl["tpl"].replace("{domain}", domain)
                    remaining_url = f"https://www.google.com/search?q={requests.utils.quote(remaining_dork)}"
                    queries.append({
                        "category": remaining_tmpl["cat"],
                        "dork": remaining_dork,
                        "description": remaining_tmpl["desc"],
                        "google_url": remaining_url,
                        "found": "skipped"
                    })
                break

        with self._results_lock:
            self.results["google_dorks"]["domain"] = domain
            self.results["google_dorks"]["queries"] = queries
            self.results["google_dorks"]["ip_blocked"] = consecutive_blocks >= 3

        print(f"{Fore.GREEN}[+] {len(queries)} Google dorks generados para {domain}")

    # -----------------------------
    # v4.4: Firebase probing
    # -----------------------------
    def _probe_firebase_access(self, base_origin: str):
        """Probe discovered Firebase resources for open read access."""
        if not self.probe_firebase:
            return

        print(f"{Fore.CYAN}[*] Probing Firebase para acceso abierto...")

        # Collect project IDs and storage buckets from parsed configs
        project_ids: Set[str] = set()
        storage_buckets: Set[str] = set()
        collections: Set[str] = set()

        with self._results_lock:
            for cfg in self.results.get("firebase", {}).get("configs_parsed", []):
                fields = cfg.get("fields", {})
                pid = fields.get("projectId")
                if pid:
                    project_ids.add(pid)
                sb = fields.get("storageBucket")
                if sb:
                    storage_buckets.add(sb)
            for col in self.results.get("firebase", {}).get("collections_probable", []):
                name = col.get("name")
                if name:
                    collections.add(name)

        if not project_ids and not storage_buckets:
            with self._results_lock:
                self.results["notes"].append("Firebase probing: no se encontraron projectId ni storageBucket para probar.")
            return

        # 1. Test RTDB open read
        for pid in project_ids:
            rtdb_url = f"https://{pid}-default-rtdb.firebaseio.com/.json?shallow=true"
            print(f"{Fore.BLUE}[*] RTDB probe: {rtdb_url}")
            fr = self.fetch(rtdb_url)
            if self.sleep_between:
                time.sleep(self.sleep_between)
            if fr and fr.status == 200 and fr.text and fr.text.strip() != "null":
                try:
                    data = json.loads(fr.text)
                    keys = list(data.keys())[:20] if isinstance(data, dict) else []
                except Exception:
                    keys = []
                self.add_finding(self.results["firebase_probing"]["rtdb_open"], {
                    "project": pid,
                    "url": rtdb_url,
                    "status": fr.status,
                    "keys_sample": keys,
                    "open": True,
                })
                print(f"{Fore.RED}[!] RTDB ABIERTO: {rtdb_url} → keys: {keys}")
            elif fr:
                self.add_finding(self.results["firebase_probing"]["rtdb_open"], {
                    "project": pid,
                    "url": rtdb_url,
                    "status": fr.status,
                    "open": False,
                })

            # Also try without -default-rtdb
            rtdb_url2 = f"https://{pid}.firebaseio.com/.json?shallow=true"
            if rtdb_url2 != rtdb_url:
                fr2 = self.fetch(rtdb_url2)
                if self.sleep_between:
                    time.sleep(self.sleep_between)
                if fr2 and fr2.status == 200 and fr2.text and fr2.text.strip() != "null":
                    try:
                        data = json.loads(fr2.text)
                        keys = list(data.keys())[:20] if isinstance(data, dict) else []
                    except Exception:
                        keys = []
                    self.add_finding(self.results["firebase_probing"]["rtdb_open"], {
                        "project": pid,
                        "url": rtdb_url2,
                        "status": fr2.status,
                        "keys_sample": keys,
                        "open": True,
                    })
                    print(f"{Fore.RED}[!] RTDB ABIERTO: {rtdb_url2} → keys: {keys}")

        # 2. Test Firestore open read per collection
        for pid in project_ids:
            for col in list(collections)[:15]:
                fs_url = f"https://firestore.googleapis.com/v1/projects/{pid}/databases/(default)/documents/{col}?pageSize=1"
                print(f"{Fore.BLUE}[*] Firestore probe: {col} @ {pid}")
                fr = self.fetch(fs_url)
                if self.sleep_between:
                    time.sleep(self.sleep_between)
                if fr and fr.status == 200 and fr.text:
                    try:
                        data = json.loads(fr.text)
                        docs = data.get("documents", [])
                        doc_count = len(docs)
                    except Exception:
                        doc_count = 0
                    self.add_finding(self.results["firebase_probing"]["firestore_open"], {
                        "project": pid,
                        "collection": col,
                        "url": fs_url,
                        "status": fr.status,
                        "docs_returned": doc_count,
                        "open": True,
                    })
                    print(f"{Fore.RED}[!] Firestore ABIERTO: {col} @ {pid} ({doc_count} docs)")
                elif fr:
                    if fr.status in (403, 401):
                        pass  # protected, skip
                    else:
                        self.add_finding(self.results["firebase_probing"]["firestore_open"], {
                            "project": pid,
                            "collection": col,
                            "url": fs_url,
                            "status": fr.status,
                            "open": False,
                        })

        # 3. Test Storage bucket listing
        for sb in storage_buckets:
            storage_url = f"https://firebasestorage.googleapis.com/v0/b/{sb}/o?maxResults=5"
            print(f"{Fore.BLUE}[*] Storage probe: {sb}")
            fr = self.fetch(storage_url)
            if self.sleep_between:
                time.sleep(self.sleep_between)
            if fr and fr.status == 200 and fr.text:
                try:
                    data = json.loads(fr.text)
                    items = data.get("items", [])
                    names = [it.get("name", "") for it in items[:10]]
                except Exception:
                    names = []
                self.add_finding(self.results["firebase_probing"]["storage_open"], {
                    "bucket": sb,
                    "url": storage_url,
                    "status": fr.status,
                    "files_sample": names,
                    "open": True,
                })
                print(f"{Fore.RED}[!] Storage ABIERTO: {sb} → files: {names}")
            elif fr:
                self.add_finding(self.results["firebase_probing"]["storage_open"], {
                    "bucket": sb,
                    "url": storage_url,
                    "status": fr.status,
                    "open": False,
                })

        print(f"{Fore.GREEN}[+] Firebase probing completado.")

    # -----------------------------
    # App stack identification
    # -----------------------------
    def _identify_app_stack(self):
        """Build a human-readable summary of the detected app stack."""
        with self._results_lock:
            fps = list(self.results.get("fingerprints") or [])
            fw = list(self.results.get("framework_hints") or [])
            backend = list(self.results.get("backend_hints") or [])
            techs = list(self.results.get("technologies") or [])

        frontend_fw: List[str] = []
        backend_fw: List[str] = []

        all_hints = " ".join(fps + fw + techs).lower()

        # Frontend framework detection
        if "next.js" in all_hints or "nextjs" in all_hints or self.results.get("nextjs", {}).get("detected"):
            frontend_fw.append("Next.js")
        if "react" in all_hints and "Next.js" not in frontend_fw:
            frontend_fw.append("React")
        if "angular" in all_hints:
            frontend_fw.append("Angular")
        if "nuxt" in all_hints:
            frontend_fw.append("Nuxt")
        if "vue" in all_hints and "Nuxt" not in frontend_fw:
            frontend_fw.append("Vue")
        if "svelte" in all_hints:
            frontend_fw.append("Svelte")
        if "remix" in all_hints:
            frontend_fw.append("Remix")
        if "gatsby" in all_hints:
            frontend_fw.append("Gatsby")
        if "astro" in all_hints:
            frontend_fw.append("Astro")

        # Backend framework detection from backend_hints
        for hint in backend:
            hl = hint.lower()
            if "django" in hl and "Django" not in backend_fw:
                backend_fw.append("Django (Python)")
            if "flask" in hl and "Flask" not in backend_fw:
                backend_fw.append("Flask (Python)")
            if "fastapi" in hl and "FastAPI" not in backend_fw:
                backend_fw.append("FastAPI (Python)")
            if "laravel" in hl and "Laravel" not in backend_fw:
                backend_fw.append("Laravel (PHP)")
            if "ruby on rails" in hl and "Ruby on Rails" not in backend_fw:
                backend_fw.append("Ruby on Rails")
            if "spring" in hl and "Spring Boot" not in backend_fw:
                backend_fw.append("Spring Boot (Java)")
            if "asp.net" in hl or ".net" in hl:
                if "ASP.NET" not in backend_fw:
                    backend_fw.append("ASP.NET")
            if "express" in hl and "Express.js" not in backend_fw:
                backend_fw.append("Express.js (Node)")
            if "node" in hl and "Node.js" not in backend_fw:
                backend_fw.append("Node.js")
            if "php" in hl and "PHP" not in backend_fw and "Laravel" not in str(backend_fw):
                backend_fw.append("PHP")
            if "wordpress" in hl and "WordPress" not in backend_fw:
                backend_fw.append("WordPress (PHP)")
            if "shopify" in hl and "Shopify" not in backend_fw:
                backend_fw.append("Shopify")
            if ("gunicorn" in hl or "uvicorn" in hl or "wsgi" in hl or "asgi" in hl) and "Python WSGI/ASGI" not in backend_fw:
                backend_fw.append("Python WSGI/ASGI")
            if ("tomcat" in hl or "java" in hl) and "Java/Tomcat" not in backend_fw:
                backend_fw.append("Java/Tomcat")

        # Services
        services: List[str] = []
        with self._results_lock:
            tp = self.results.get("third_party_services") or {}
            tp_labels = {
                "supabase": "Supabase", "auth0": "Auth0", "clerk": "Clerk",
                "stripe": "Stripe", "mixpanel": "Mixpanel", "intercom": "Intercom",
                "pusher": "Pusher", "algolia": "Algolia", "google_maps": "Google Maps",
                "mapbox": "Mapbox", "twilio": "Twilio", "onesignal": "OneSignal",
                "recaptcha": "reCAPTCHA/hCaptcha", "hotjar": "Hotjar",
                "datadog": "DataDog", "launchdarkly": "LaunchDarkly",
                "amplitude": "Amplitude", "posthog": "PostHog",
            }
            for key, label in tp_labels.items():
                if tp.get(key, {}).get("detected"):
                    services.append(label)

            if self.results.get("firebase", {}).get("detected"):
                services.append("Firebase")
            if self.results.get("exposed_configs", {}).get("aws_amplify_cognito"):
                services.append("AWS Cognito")
            if self.results.get("exposed_configs", {}).get("aws_appsync_amplify"):
                services.append("AWS AppSync")
            if self.results.get("exposed_configs", {}).get("sentry"):
                services.append("Sentry")
            if self.results.get("exposed_configs", {}).get("google_analytics"):
                services.append("Google Analytics")
            if self.results.get("exposed_configs", {}).get("segment"):
                services.append("Segment")

        # App type summary
        if frontend_fw and backend_fw:
            app_type = f"{' + '.join(frontend_fw)} | {' + '.join(backend_fw)}"
        elif frontend_fw:
            app_type = f"{' + '.join(frontend_fw)} SPA/SSR"
        elif backend_fw:
            app_type = f"Server-side ({' + '.join(backend_fw)})"
        else:
            app_type = "Web App (sin framework identificado)"

        with self._results_lock:
            self.results["stack_summary"] = {
                "app_type": app_type,
                "frontend_frameworks": frontend_fw,
                "backend_frameworks": backend_fw,
                "services": services,
            }

    # -----------------------------
    # Dedup
    # -----------------------------
    def _dedup_findings(self):
        def dedup_list_of_dict(lst: List[dict], key_fields: List[str]) -> List[dict]:
            seen = set()
            out = []
            for d in lst:
                k = tuple(d.get(f) for f in key_fields)
                if k in seen:
                    continue
                seen.add(k)
                out.append(d)
            return out

        with self._results_lock:
            self.results["technologies"] = sorted(set(self.results["technologies"]))
            self.results["fingerprints"] = sorted(set(self.results["fingerprints"]))
            self.results["backend_hints"] = uniq_list(self.results["backend_hints"])
            self.results["framework_hints"] = sorted(set(self.results.get("framework_hints") or []))

            ep = self.results["endpoints"]
            ep["absolute"] = dedup_list_of_dict(ep["absolute"], ["url", "found_in", "line"])
            ep["relative"] = dedup_list_of_dict(ep["relative"], ["full_url", "found_in", "line"])
            ep["graphql"] = dedup_list_of_dict(ep["graphql"], ["url_or_path", "found_in", "line"])
            ep["websocket"] = dedup_list_of_dict(ep["websocket"], ["url", "found_in", "line"])
            ep["base_urls"] = dedup_list_of_dict(ep["base_urls"], ["value", "found_in", "line"])
            # v4.5: Improved dedup for requests_inferred: group by (method, url) keeping best confidence
            _ri_seen: dict = {}  # key -> index in out
            _ri_out: List[dict] = []
            for item in ep["requests_inferred"]:
                k = (item.get("method", "?"), item.get("url_or_path", ""))
                conf = item.get("confidence", 0) or 0
                if k not in _ri_seen:
                    _ri_seen[k] = len(_ri_out)
                    _ri_out.append(dict(item))
                else:
                    existing = _ri_out[_ri_seen[k]]
                    existing_conf = existing.get("confidence", 0) or 0
                    if conf > existing_conf:
                        # Keep item with higher confidence but append the found_in info
                        item_copy = dict(item)
                        prev_src = existing.get("found_in", "")
                        item_copy["found_in"] = item_copy.get("found_in", "")
                        _ri_out[_ri_seen[k]] = item_copy
            # Apply min_confidence filter if set
            if self.min_confidence > 0:
                _ri_out = [x for x in _ri_out if (x.get("confidence") or 0) >= self.min_confidence]
            ep["requests_inferred"] = _ri_out
            # Also dedup tanstack, rtk, graphql
            ep["tanstack_query"] = dedup_list_of_dict(ep.get("tanstack_query", []), ["type", "url_or_path", "found_in"])
            ep["rtk_endpoints"] = dedup_list_of_dict(ep.get("rtk_endpoints", []), ["method", "url_or_path", "found_in"])
            ep["graphql_operations"] = dedup_list_of_dict(ep.get("graphql_operations", []), ["type", "name", "found_in"])
            ep["spa_routes"] = dedup_list_of_dict(ep.get("spa_routes", []), ["path", "router_type"])

            inv = self.results["inventory"]
            inv["routes_full_urls"] = dedup_list_of_dict(inv["routes_full_urls"], ["full_url", "path"])
            inv["internal_links"] = sorted(set(inv["internal_links"]))

            cfg = self.results["exposed_configs"]
            cfg["aws_amplify_cognito"] = dedup_list_of_dict(cfg["aws_amplify_cognito"], ["hit", "found_in", "line"])
            cfg["aws_appsync_amplify"] = dedup_list_of_dict(cfg["aws_appsync_amplify"], ["hit", "found_in", "line"])
            cfg["sentry"] = dedup_list_of_dict(cfg["sentry"], ["dsn", "found_in", "line"])
            cfg["google_analytics"] = dedup_list_of_dict(cfg["google_analytics"], ["id", "found_in", "line"])
            cfg["segment"] = dedup_list_of_dict(cfg["segment"], ["key", "found_in", "line"])

            fb = self.results["firebase"]
            fb["configs"] = dedup_list_of_dict(fb["configs"], ["blob", "found_in", "line"])
            fb["firestore_rest"] = dedup_list_of_dict(fb["firestore_rest"], ["url", "found_in", "line"])
            fb["rtdb"] = dedup_list_of_dict(fb["rtdb"], ["url", "found_in", "line"])
            fb["collections_probable"] = dedup_list_of_dict(fb["collections_probable"], ["name", "found_in", "evidence"])

            names_seen = set()
            compact = []
            for c in fb["collections_probable"]:
                n = c.get("name")
                if not n or n in names_seen:
                    continue
                names_seen.add(n)
                compact.append(c)
            fb["collections_probable"] = compact

            scr = self.results.get("screenshots", {}).get("routes", []) or []
            seen_k = set()
            scr2 = []
            for it in scr:
                u = normalize_url(it.get("url", "") or "")
                kind = it.get("kind") or "route"
                if not u:
                    continue
                k = (u, kind)
                if k in seen_k:
                    continue
                seen_k.add(k)
                scr2.append(it)
            self.results["screenshots"]["routes"] = scr2

            ai = self.results.get("authz_audit", {}).get("items") or []
            seen_u = set()
            ai2 = []
            for it in ai:
                u = normalize_url(it.get("url", "") or "")
                if not u or u in seen_u:
                    continue
                seen_u.add(u)
                ai2.append(it)
            if "authz_audit" in self.results:
                self.results["authz_audit"]["items"] = ai2

            # Classify each route as frontend or backend
            for r in self.results["inventory"]["routes_full_urls"]:
                if "route_type" not in r:
                    r["route_type"] = self._classify_route_type(r.get("path") or "/")

        # Build app stack summary
        self._identify_app_stack()

        # v4.5: Build frontend map
        frontend_map = self._build_frontend_map()
        with self._results_lock:
            self.results["frontend_map"] = frontend_map

    # -----------------------------
    # HTML Report rendering
    # -----------------------------
    def generate_report(self):
        out_json = os.path.join(self.out_dir, "results.json")
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(self.results, f, ensure_ascii=False, indent=2)

        template = read_text_file(self.template_path)
        payload = json.dumps(self.results, ensure_ascii=False)
        html = template.replace("__RESULTS_JSON__", payload)

        out_html = os.path.join(self.out_dir, "index.html")
        with open(out_html, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"\n{Fore.GREEN}[+] Reporte generado: {out_html}")
        print(f"{Fore.GREEN}[+] JSON generado: {out_json}")
        print(f"{Fore.GREEN}[+] Template (editable): {self.template_path}")

    # -----------------------------
    # ReactScan
    # -----------------------------
    def _run_reactscan(self):
        """Ejecuta el módulo ReactScan: detección de librerías, CVEs activos (sin flag --test)."""
        url = self.results.get("final_url") or self.target_url
        print(f"{Fore.CYAN}[ReactScan] Iniciando análisis de seguridad React/Next.js en: {url}")

        try:
            sess = self._get_session()
            resp = sess.get(url, timeout=self.request_timeout, verify=False)
            html = resp.text or ""
        except Exception as e:
            with self._results_lock:
                self.results["notes"].append(f"ReactScan fetch error: {e}")
            return

        with self._results_lock:
            self.results["reactscan"]["tech_results"] = rs_check_technology(resp, html)

        print(f"{Fore.CYAN}[ReactScan] Escaneando librerías y vulnerabilidades OSV.dev...")
        libs = rs_check_libraries_and_vulns(url, html)
        with self._results_lock:
            self.results["reactscan"]["libs_results"] = libs

        print(f"{Fore.CYAN}[ReactScan] Buscando archivos sensibles...")
        files = rs_check_sensitive_files(url)
        with self._results_lock:
            self.results["reactscan"]["files_results"] = files

        print(f"{Fore.CYAN}[ReactScan] Buscando Source Maps...")
        maps = rs_check_source_maps(url, html)
        with self._results_lock:
            self.results["reactscan"]["map_results"] = maps

        print(f"{Fore.CYAN}[ReactScan] Comprobando CVEs Next.js/React (pasivo)...")
        cves = rs_check_nextjs_cves(url, html)
        with self._results_lock:
            self.results["reactscan"]["cve_results"] = cves

        print(f"{Fore.CYAN}[ReactScan] Verificación activa de CVEs (sin --test requerido)...")
        active = rs_run_active_cve_tests(url, html)
        with self._results_lock:
            self.results["reactscan"]["active_cve_results"] = active

        total_critical = sum(1 for r in (libs + files + maps + cves + active) if r.get("type") == "critical")
        total_high = sum(1 for r in (libs + files + maps + cves + active) if r.get("type") == "high")
        print(f"{Fore.RED if total_critical else Fore.YELLOW}[ReactScan] Completado — critical: {total_critical}, high: {total_high}")

    # -----------------------------
    # Run
    # -----------------------------
    def run(self):
        self.print_banner()
        self.identify_tech_wappalyzer()
        self.scan_source_and_assets()
        self._run_reactscan()
        self.generate_report()
        print(f"\n{Fore.MAGENTA}Darkmoon • Security Reporting")


# =============================
# CLI helpers
# =============================
def parse_headers(args: argparse.Namespace) -> Dict[str, str]:
    headers: Dict[str, str] = {}

    if args.header:
        for hv in args.header:
            if ":" not in hv:
                continue
            k, v = hv.split(":", 1)
            k = k.strip()
            v = v.strip()
            if k:
                headers[k] = v

    if args.headers_json:
        try:
            with open(args.headers_json, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(k, str):
                        headers[k] = str(v)
        except Exception as e:
            print(f"{Fore.YELLOW}[!] No pude leer headers-json: {e}")

    if args.bearer:
        headers["Authorization"] = f"Bearer {args.bearer.strip()}"

    return headers


def _ai_prefs_path() -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, ".darkmlens_ai_prefs.json")


def _load_ai_prefs() -> Dict[str, str]:
    path = _ai_prefs_path()
    if not os.path.isfile(path):
        return {}
    try:
        data = json.loads(read_text_file(path))
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def _save_ai_prefs(provider: str, model: str, ollama_url: str = "", lm_studio_url: str = ""):
    payload = {
        "ai_provider": provider or "",
        "ai_model": model or "",
        "ollama_url": ollama_url or "",
        "lm_studio_url": lm_studio_url or "",
        "updated_at": int(time.time()),
    }
    try:
        write_text_file(_ai_prefs_path(), json.dumps(payload, ensure_ascii=False, indent=2))
    except Exception:
        pass


def _reset_ai_prefs() -> bool:
    path = _ai_prefs_path()
    try:
        if os.path.isfile(path):
            os.remove(path)
        return True
    except Exception:
        return False


def apply_saved_ai_defaults(args):
    """Carga defaults AI guardados cuando el usuario no los pasó explícitamente."""
    if not getattr(args, "ai_js_extract", False):
        return

    prefs = _load_ai_prefs()
    if not prefs:
        return

    saved_provider = (prefs.get("ai_provider") or "").strip()
    saved_model = (prefs.get("ai_model") or "").strip()
    saved_ollama = (prefs.get("ollama_url") or "").strip()
    saved_lm = (prefs.get("lm_studio_url") or "").strip()

    if not getattr(args, "ai_provider", None) and saved_provider:
        args.ai_provider = saved_provider

    if getattr(args, "ai_model", "") == "dolphin-llama3:latest" and saved_model:
        args.ai_model = saved_model

    if getattr(args, "ai_provider", "") == "ollama" and getattr(args, "ollama_url", "") == "http://localhost:11434" and saved_ollama:
        args.ollama_url = saved_ollama

    if getattr(args, "ai_provider", "") == "lm_studio" and saved_lm:
        setattr(args, "lm_studio_url", saved_lm)


def interactive_ai_setup(args):
    import sys
    if not args.ai_js_extract or getattr(args, "ai_provider", None):
        if not getattr(args, "ai_provider", None):
            args.ai_provider = "claude"
        return

    if not sys.stdout.isatty():
        args.ai_provider = "claude"
        return

    prefs = _load_ai_prefs()
    saved_provider = (prefs.get("ai_provider") or "").strip()
    saved_model = (prefs.get("ai_model") or "").strip()
    saved_ollama = (prefs.get("ollama_url") or "").strip()
    saved_lm = (prefs.get("lm_studio_url") or "").strip()

    default_choice = "1"
    if saved_provider == "ollama":
        default_choice = "2"
    elif saved_provider == "lm_studio":
        default_choice = "3"
    elif saved_provider == "claude_code":
        default_choice = "4"

    print(f"\n{Fore.CYAN}[AI] Análisis Inteligente JS habilitado.")
    if saved_provider:
        print(f"{Fore.GREEN}[*] Config guardada: provider={saved_provider} model={saved_model or '-'}")
        if saved_provider == "ollama" and saved_ollama:
            print(f"{Fore.GREEN}[*] Ollama URL guardada: {saved_ollama}")
        if saved_provider == "lm_studio" and saved_lm:
            print(f"{Fore.GREEN}[*] LM Studio URL guardada: {saved_lm}")
    print("¿Qué motor deseas utilizar para extraer las rutas JS?")
    print(f"  {Fore.YELLOW}1){Style.RESET_ALL} Claude (Requiere API Key)")
    print(f"  {Fore.YELLOW}2){Style.RESET_ALL} Ollama (Local)")
    print(f"  {Fore.YELLOW}3){Style.RESET_ALL} LM Studio (Local o Remoto)")
    print(f"  {Fore.YELLOW}4){Style.RESET_ALL} Claude Code (Local CLI sobre todos los JS descargados)")
    
    choice = input(f"Elige una opción [1/2/3/4] (por defecto {default_choice}): ").strip()
    if not choice:
        choice = default_choice
    
    if choice == "3":
        args.ai_provider = "lm_studio"
        lm_default = saved_lm or "127.0.0.1:1234"
        lm_ip = input(f"Ingresa IP y Puerto de LM Studio (ej. 127.0.0.1:1234) [Enter={lm_default}]: ").strip()
        if not lm_ip:
            lm_ip = lm_default
        if not lm_ip.startswith("http"):
            lm_ip = f"http://{lm_ip}"
        setattr(args, "lm_studio_url", lm_ip)
        
        try:
            r = requests.get(f"{lm_ip}/v1/models", timeout=5)
            if r.status_code == 200:
                models_data = r.json().get("data", [])
                if not models_data:
                    print(f"{Fore.RED}[!] LM Studio está funcionando pero sin modelos cargados.")
                    args.ai_model = "local-model"
                else:
                    print(f"\n{Fore.GREEN}[+] LM Studio detectado en {lm_ip}")
                    valid_models = [m.get("id") for m in models_data if m.get("id")]
                    for i, mname in enumerate(valid_models):
                        print(f"  {Fore.YELLOW}{i+1}){Style.RESET_ALL} {mname}")
                    remembered_model = saved_model if saved_model in valid_models else ""
                    prompt_model = f"Selecciona el modelo [1-{len(valid_models)}]"
                    if remembered_model:
                        prompt_model += f" [Enter={remembered_model}]"
                    prompt_model += ": "
                    m_choice = input(prompt_model).strip()
                    if not m_choice and remembered_model:
                        args.ai_model = remembered_model
                    else:
                        try:
                            idx = int(m_choice) - 1
                            if 0 <= idx < len(valid_models):
                                args.ai_model = valid_models[idx]
                            else:
                                print(f"{Fore.YELLOW}[!] Opción inválida. Usando {valid_models[0]}.")
                                args.ai_model = valid_models[0]
                        except ValueError:
                            print(f"{Fore.YELLOW}[!] Usando {valid_models[0]} por defecto.")
                            args.ai_model = valid_models[0]
                print(f"{Fore.GREEN}[*] Proveedor AI: LM Studio | Modelo: {args.ai_model}")
                _save_ai_prefs("lm_studio", args.ai_model, lm_studio_url=lm_ip)
            else:
                print(f"{Fore.RED}[!] Error HTTP {r.status_code} conectando a LM Studio.")
                args.ai_model = "local-model"
                _save_ai_prefs("lm_studio", args.ai_model, lm_studio_url=lm_ip)
        except Exception:
            print(f"{Fore.RED}[!] No se pudo conectar a LM Studio en {lm_ip}")
            print(f"{Fore.YELLOW}[!] Usando modelo por defecto.")
            args.ai_model = "local-model"
            _save_ai_prefs("lm_studio", args.ai_model, lm_studio_url=lm_ip)
    elif choice == "2":
        args.ai_provider = "ollama"
        ollama_default = saved_ollama or "localhost:11434"
        ollama_ip = input(f"Ingresa URL de Ollama (ej. localhost:11434) [Enter={ollama_default}]: ").strip()
        if not ollama_ip:
            ollama_ip = ollama_default
        if not ollama_ip.startswith("http"):
            ollama_ip = f"http://{ollama_ip}"
        setattr(args, "ollama_url", ollama_ip)
        try:
            r = requests.get(f"{ollama_ip}/api/tags", timeout=3)
            if r.status_code == 200:
                models = r.json().get("models", [])
                if not models:
                    print(f"{Fore.RED}[!] Ollama está corriendo pero no tienes modelos instalados.")
                    args.ai_model = "dolphin-llama3:latest" # default fallback
                else:
                    print(f"\n{Fore.GREEN}[+] Ollama detectado en {ollama_ip}")
                    valid_models = [m.get('name') for m in models if m.get('name')]
                    for i, mname in enumerate(valid_models):
                        print(f"  {Fore.YELLOW}{i+1}){Style.RESET_ALL} {mname}")
                    remembered_model = saved_model if saved_model in valid_models else ""
                    prompt_model = f"Selecciona el modelo [1-{len(valid_models)}]"
                    if remembered_model:
                        prompt_model += f" [Enter={remembered_model}]"
                    prompt_model += ": "
                    m_choice = input(prompt_model).strip()
                    if not m_choice and remembered_model:
                        args.ai_model = remembered_model
                    else:
                        try:
                            idx = int(m_choice) - 1
                            if 0 <= idx < len(valid_models):
                                args.ai_model = valid_models[idx]
                            else:
                                print(f"{Fore.YELLOW}[!] Opción inválida. Usando {valid_models[0]} por defecto.")
                                args.ai_model = valid_models[0]
                        except ValueError:
                            print(f"{Fore.YELLOW}[!] Usando {valid_models[0]} por defecto.")
                            args.ai_model = valid_models[0]
                    
                print(f"{Fore.GREEN}[*] Proveedor AI: Ollama | Modelo: {args.ai_model}")
                _save_ai_prefs("ollama", args.ai_model, ollama_url=ollama_ip)
            else:
                print(f"{Fore.RED}[!] Error HTTP {r.status_code} al conectar a Ollama.")
                _save_ai_prefs("ollama", args.ai_model, ollama_url=ollama_ip)
        except Exception:
            print(f"{Fore.RED}[!] No se pudo conectar a Ollama. Asegúrate de ejecutar 'ollama serve' en otra terminal.")
            print(f"{Fore.YELLOW}[!] Se intentará ejecutar Ollama a ciegas con modelo por defecto.")
            args.ai_model = "dolphin-llama3:latest"
            _save_ai_prefs("ollama", args.ai_model, ollama_url=ollama_ip)
    elif choice == "4":
        args.ai_provider = "claude_code"
        _save_ai_prefs("claude_code", args.ai_model)
        print(f"{Fore.GREEN}[*] Proveedor AI: Claude Code (Local CLI)")
    else:
        args.ai_provider = "claude"
        if not args.ai_api_key:
            key = input(f"Ingresa tu API Key de Claude: ").strip()
            args.ai_api_key = key
        _save_ai_prefs("claude", args.ai_model)
        print(f"{Fore.GREEN}[*] Proveedor AI: Claude")

def _cmd_report_from_json(json_path: str, template_path: str = None):
    """Regenera el HTML desde un results.json existente sin re-escanear."""
    import os, json
    json_path = os.path.abspath(json_path)
    if not os.path.isfile(json_path):
        print(f"{Fore.RED}[!] No se encontró: {json_path}")
        return 1
    out_dir = os.path.dirname(json_path)
    with open(json_path, "r", encoding="utf-8") as f:
        results = json.load(f)

    # Resolve template — try several candidate locations
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = []
    if template_path:
        candidates.append(template_path)
    candidates += [
        os.path.join(out_dir, "report.template.html"),
        os.path.join(out_dir, "template.html"),
        os.path.join(script_dir, "template.html"),
        os.path.join(script_dir, "templates", "default.template.html"),
        os.path.join(script_dir, "templates", "template.html"),
    ]
    template_path = None
    template = None
    for candidate in candidates:
        if not os.path.isfile(candidate):
            continue
        try:
            candidate_text = read_text_file(candidate)
        except Exception:
            continue
        if "__RESULTS_JSON__" in candidate_text:
            template_path = candidate
            template = candidate_text
            break

    if template is None:
        template_path = "<embedded DEFAULT_REPORT_TEMPLATE>"
        template = DEFAULT_REPORT_TEMPLATE

    payload = json.dumps(results, ensure_ascii=False)
    html = template.replace("__RESULTS_JSON__", payload)
    out_html = os.path.join(out_dir, "index.html")
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"{Fore.GREEN}[+] HTML regenerado: {out_html}")
    return 0


def main():
    p = argparse.ArgumentParser(description="DarkmLens v4.4 (Darkmoon) - Passive exposure report + active recon (authorized only)")
    p.add_argument("url", nargs="?", default=None, help="Target URL (https://example.com/path)")
    p.add_argument("--out", default="out", help="Output folder")
    p.add_argument("--report-from-json", metavar="PATH", default=None,
                   help="Regenera el HTML desde un results.json existente sin re-escanear. Ej: --report-from-json out/site/results.json")
    p.add_argument("--template", metavar="PATH", default=None,
                   help="Ruta al template HTML (usado con --report-from-json si no hay template.html en la misma carpeta)")
    p.add_argument("--reset-ai-prefs", action="store_true",
                   help="Borra preferencias AI guardadas (provider/model/IP) y sale")
    p.add_argument("--max-assets", type=int, default=120, help="Max same-origin assets to fetch")
    p.add_argument("--max-maps", type=int, default=20, help="Max sourcemaps to fetch")
    p.add_argument("--timeout", type=int, default=15, help="Request timeout seconds")
    p.add_argument("--sleep", type=float, default=0.03, help="Sleep between fetches (per request). Set 0 for max speed (risky).")
    p.add_argument("--no-screenshot", action="store_true", help="Disable screenshots (Playwright)")

    p.add_argument("--no-crawl", action="store_true", help="Disable same-origin crawling of pages")
    p.add_argument("--max-pages", type=int, default=40, help="Max pages to visit (crawl)")
    p.add_argument("--max-depth", type=int, default=4, help="Max crawl depth")

    # v4.5: Sitemap + confidence
    p.add_argument("--no-sitemap", action="store_true", help="Skip sitemap.xml / robots.txt seed probe")
    p.add_argument("--min-confidence", type=int, default=0, help="Filter requests_inferred to entries with confidence >= N (0 = show all)")

    p.add_argument("--header", action="append", help='Extra header (repeatable): "Key: Value"')
    p.add_argument("--headers-json", help="JSON file with headers dict")
    p.add_argument("--bearer", help="Convenience: Bearer token -> Authorization header")

    p.add_argument("--no-save-bodies", action="store_true", help="Do not save per-route response bodies")
    p.add_argument("--probe-get", action="store_true", help="Probe some inferred same-origin GET endpoints (safe-ish)")

    # AuthZ audit
    p.add_argument("--audit-authz", action="store_true", help="Visit discovered same-origin routes and classify access")
    p.add_argument("--authz-max-routes", type=int, default=200, help="Max routes to test in authz audit")
    p.add_argument("--audit-authz-limit", type=int, default=None, help="Alias of --authz-max-routes")
    p.add_argument("--authz-no-screenshot-all", action="store_true", help="AuthZ audit: do not take screenshots (still visits routes)")
    p.add_argument("--authz-show-response", action="store_true", help="AuthZ audit: store a small response snippet in results/report")
    p.add_argument("--authz-response-chars", type=int, default=900, help="How many chars of response snippet to include")

    # AI analysis (Claude by default, Ollama legacy)
    p.add_argument("--ai-ollama", action="store_true", help="Use local Ollama to summarize each route (optional, legacy)")
    p.add_argument("--ai-js-extract", action="store_true", help="Use Claude/Ollama API to deeply analyze JS assets: endpoints, keys, Firebase, structure")
    p.add_argument("--ai-provider", default=None, help="Force AI provider: claude, ollama, lm_studio o claude_code. Bypasses interactive menu.")
    p.add_argument("--ai-api-key", default="", help="Anthropic (Claude) API key for --ai-js-extract analysis")
    p.add_argument("--ollama-url", default="http://localhost:11434", help="URL de la API de Ollama (default: http://localhost:11434)")
    p.add_argument("--ai-model", default="dolphin-llama3:latest", help="Model name for Ollama/LM Studio when aplica (default: dolphin-llama3:latest)")
    p.add_argument("--claude-code-extra-prompt", default="", help="Texto extra para inyectar en el prompt de Claude Code.")
    p.add_argument("--claude-code-prompt-file", default="", help="Archivo .txt/.md con instrucciones extra para Claude Code.")
    p.add_argument("--claude-code-bin", default="claude", help="Binario/ejecutable de Claude Code (default: claude)")
    p.add_argument("--claude-code-timeout", type=int, default=180, help="Timeout en segundos para la ejecución de Claude Code (default: 180)")

    # Deep endpoints
    p.add_argument("--deep-endpoints", action="store_true",
                   help="Deep endpoint discovery: for each visited HTML page, analyze its same-origin <script src> JS to extract endpoints.")
    p.add_argument("--verbose", action="store_true", help="Verbose: print each page/asset being fetched.")

    # THREADS
    p.add_argument("--threads", type=int, default=12, help="Global thread count (default 12)")
    p.add_argument("--asset-threads", type=int, default=None, help="Threads for asset fetching (default: --threads)")
    p.add_argument("--crawl-threads", type=int, default=None, help="Threads for crawl worker queue (default: min(--threads,10))")
    p.add_argument("--authz-threads", type=int, default=None, help="Threads for authz audit (default: min(--threads,20))")
    p.add_argument("--deep-threads", type=int, default=None, help="Threads for deep-endpoints script fetch (default: min(--threads,10))")

    # v4.4: Fuzzing
    p.add_argument("--fuzz", action="store_true", help="Enable directory fuzzing (active recon, off by default)")
    p.add_argument("--fuzz-wordlist", help="Custom wordlist file (one path per line, extends built-in list)")
    p.add_argument("--fuzz-threads", type=int, default=None, help="Threads for fuzzing (default: min(--threads,20))")
    p.add_argument("--fuzz-max", type=int, default=500, help="Max paths to fuzz (default 500)")

    # v4.4: Google dorks
    p.add_argument("--no-dorks", action="store_true", help="Disable Google dork generation")

    # v4.4: Firebase probing
    p.add_argument("--probe-firebase", action="store_true", help="Probe Firebase for open RTDB/Firestore/Storage (active, off by default)")

    args = p.parse_args()

    if args.reset_ai_prefs:
        ok = _reset_ai_prefs()
        if ok:
            print(f"{Fore.GREEN}[+] Preferencias AI borradas.")
            return
        print(f"{Fore.RED}[!] No se pudieron borrar las preferencias AI.")
        return

    # Reuse last AI provider/model/IP when user did not pass them explicitly.
    apply_saved_ai_defaults(args)

    # --report-from-json: regenerar HTML sin escanear
    if args.report_from_json:
        import sys
        sys.exit(_cmd_report_from_json(args.report_from_json, getattr(args, "template", None)))

    if not args.url:
        p.error("Se requiere una URL objetivo o usa --report-from-json <path>")

    # Interactive setup
    interactive_ai_setup(args)

    if args.audit_authz_limit is not None:
        args.authz_max_routes = args.audit_authz_limit

    target = args.url.strip()
    if not target.startswith("http"):
        target = "https://" + target

    extra_headers = parse_headers(args)

    s = DarkmLens(
        target_url=target,
        out_dir=args.out,
        max_assets=args.max_assets,
        max_map_files=args.max_maps,
        request_timeout=args.timeout,
        sleep_between=args.sleep,
        screenshot=not args.no_screenshot,
        crawl_pages=not args.no_crawl,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        extra_headers=extra_headers,
        save_route_bodies=not args.no_save_bodies,
        probe_get_endpoints=args.probe_get,

        audit_authz=args.audit_authz,
        authz_max_routes=args.authz_max_routes,
        authz_take_screenshots=(not args.authz_no_screenshot_all),
        authz_show_response=args.authz_show_response,
        authz_response_chars=args.authz_response_chars,

        ai_ollama=args.ai_ollama,
        ai_provider=getattr(args, "ai_provider", "claude"),
        ai_js_extract=args.ai_js_extract,
        ai_model=args.ai_model,
        ai_api_key=args.ai_api_key,
        claude_code_extra_prompt=args.claude_code_extra_prompt,
        claude_code_prompt_file=args.claude_code_prompt_file,
        claude_code_bin=args.claude_code_bin,
        claude_code_timeout=args.claude_code_timeout,
        lm_studio_url=getattr(args, "lm_studio_url", ""),
        ollama_url=getattr(args, "ollama_url", "http://localhost:11434"),

        deep_endpoints=args.deep_endpoints,

        # v4.4
        fuzz=args.fuzz,
        fuzz_wordlist_file=args.fuzz_wordlist,
        fuzz_max=args.fuzz_max,
        fuzz_threads=args.fuzz_threads,
        google_dorks=not args.no_dorks,
        probe_firebase=args.probe_firebase,

        # v4.5
        probe_sitemap=not args.no_sitemap,
        min_confidence=args.min_confidence,

        threads=args.threads,
        asset_threads=args.asset_threads,
        crawl_threads=args.crawl_threads,
        authz_threads=args.authz_threads,
        deep_threads=args.deep_threads,
    )
    s.verbose = args.verbose

    try:
        s.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrumpido por el usuario. Generando reporte parcial...")
        try:
            s._stop_event.set()
            s._dedup_findings()
            s.generate_report()
            print(f"{Fore.GREEN}[+] Reporte parcial guardado en: {os.path.join(s.out_dir, 'index.html')}")
        except Exception as e:
            print(f"{Fore.RED}[!] No pude generar el reporte parcial: {e}")


# =============================
# Default HTML template written to out/report.template.html
# =============================
DEFAULT_REPORT_TEMPLATE = r"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>DarkmLens — Reporte de Exposición</title>
  <style>
    :root{
      --bg:#07090d; --panel:#0d1117; --card:#0f1622; --border:#1a2535;
      --txt:#dce8f5; --muted:#7d8fa3; --accent:#4fffb0; --accent2:#b24bfe;
      --red:#ff4d6d; --orange:#ffaa00; --blue:#3fa0ff; --purple:#9d4edd;
      --green:#20c997; --yellow:#ffd166;
    }
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Arial;background:var(--bg);color:var(--txt);min-height:100vh}
    body::before{content:'';position:fixed;top:0;left:0;right:0;height:500px;background:radial-gradient(ellipse 80% 60% at 50% -10%,rgba(75,150,255,0.08) 0%,transparent 70%);pointer-events:none}
    a{color:var(--accent);text-decoration:none}
    a:hover{text-decoration:underline}
    code{background:rgba(255,255,255,0.05);padding:2px 7px;border-radius:6px;border:1px solid rgba(255,255,255,0.07);font-family:monospace;font-size:11px}
    .wrap{max-width:1340px;margin:0 auto;padding:28px 20px}

    /* ── NAV ── */
    .nav{display:flex;align-items:center;gap:12px;flex-wrap:wrap;border-bottom:1px solid var(--border);padding-bottom:18px;margin-bottom:24px}
    .nav-logo{font-size:20px;font-weight:700;letter-spacing:-0.5px}
    .nav-logo span{color:var(--accent2)}
    .nav-badge{padding:3px 10px;border-radius:999px;border:1px solid rgba(177,75,254,0.35);background:rgba(177,75,254,0.07);color:var(--accent2);font-size:11px;font-weight:600}
    .nav-right{margin-left:auto;color:var(--muted);font-size:12px}

    /* ── HERO ── */
    .hero{display:grid;grid-template-columns:1fr auto;gap:20px;align-items:start;margin-bottom:24px}
    @media(max-width:700px){.hero{grid-template-columns:1fr}}
    .hero-title{font-size:28px;font-weight:700;line-height:1.2;margin-bottom:8px}
    .hero-title .hl{color:var(--accent)}
    .hero-url{font-size:13px;color:var(--muted);word-break:break-all;margin-bottom:12px}
    .hero-meta{display:flex;gap:8px;flex-wrap:wrap}
    .meta-pill{display:inline-flex;align-items:center;gap:6px;padding:5px 12px;border-radius:999px;border:1px solid var(--border);background:rgba(255,255,255,0.02);font-size:12px;color:var(--muted)}
    .meta-pill b{color:var(--txt)}
    .hero-box{min-width:260px;background:rgba(255,255,255,0.02);border:1px solid var(--border);border-radius:14px;padding:16px}

    /* ── APP STACK ── */
    .stack-card{background:linear-gradient(135deg,rgba(79,255,176,0.04) 0%,rgba(177,75,254,0.06) 100%);border:1px solid rgba(79,255,176,0.15);border-radius:16px;padding:20px;margin-bottom:24px}
    .stack-title{font-size:13px;font-weight:600;color:var(--accent);text-transform:uppercase;letter-spacing:.08em;margin-bottom:14px}
    .stack-type{font-size:22px;font-weight:700;margin-bottom:16px;color:var(--txt)}
    .stack-cols{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
    @media(max-width:700px){.stack-cols{grid-template-columns:1fr}}
    .stack-col-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px}
    .fw-badge{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border-radius:999px;font-size:13px;font-weight:600;margin:3px}
    .fw-fe{background:rgba(63,160,255,0.10);border:1px solid rgba(63,160,255,0.30);color:var(--blue)}
    .fw-be{background:rgba(157,78,221,0.10);border:1px solid rgba(157,78,221,0.30);color:var(--purple)}
    .fw-svc{background:rgba(79,255,176,0.08);border:1px solid rgba(79,255,176,0.20);color:var(--accent)}

    /* ── STATS ROW ── */
    .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px}
    .stat{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:16px;text-align:center}
    .stat-n{font-size:28px;font-weight:700;color:var(--accent);line-height:1}
    .stat-l{font-size:11px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.05em}

    /* ── SECTIONS/TABS ── */
    .section{margin-bottom:28px}
    .section-h{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:8px}
    .section-title{font-size:16px;font-weight:700;display:flex;align-items:center;gap:10px}
    .section-title .ico{width:28px;height:28px;border-radius:8px;display:inline-flex;align-items:center;justify-content:center;font-size:14px}
    .ico-blue{background:rgba(63,160,255,0.12);color:var(--blue)}
    .ico-purple{background:rgba(157,78,221,0.12);color:var(--purple)}
    .ico-orange{background:rgba(255,170,0,0.12);color:var(--orange)}
    .ico-green{background:rgba(32,201,151,0.12);color:var(--green)}
    .ico-red{background:rgba(255,77,109,0.12);color:var(--red)}
    .ico-accent{background:rgba(79,255,176,0.12);color:var(--accent)}
    .count-badge{padding:3px 10px;border-radius:999px;background:rgba(255,255,255,0.06);border:1px solid var(--border);color:var(--muted);font-size:11px}

    /* ── CARDS ── */
    .card{background:var(--card);border:1px solid var(--border);border-radius:16px;overflow:hidden}
    .card-h{padding:13px 16px;border-bottom:1px solid var(--border);background:rgba(255,255,255,0.015);display:flex;justify-content:space-between;align-items:center;gap:10px;cursor:pointer;user-select:none}
    .card-h h2{font-size:14px;font-weight:600}
    .card-b{padding:14px 16px}
    .card-full{grid-column:1/-1}

    /* ── GRID ── */
    .grid2{display:grid;grid-template-columns:1fr 1fr;gap:18px}
    @media(max-width:900px){.grid2{grid-template-columns:1fr}}

    /* ── BADGES ── */
    .badges{display:flex;flex-wrap:wrap;gap:7px}
    .badge{padding:5px 11px;border-radius:999px;font-size:12px;font-weight:500}
    .badge-green{background:rgba(79,255,176,0.08);border:1px solid rgba(79,255,176,0.25);color:var(--accent)}
    .badge-blue{background:rgba(63,160,255,0.10);border:1px solid rgba(63,160,255,0.30);color:var(--blue)}
    .badge-red{background:rgba(255,77,109,0.10);border:1px solid rgba(255,77,109,0.30);color:var(--red)}
    .badge-orange{background:rgba(255,170,0,0.10);border:1px solid rgba(255,170,0,0.30);color:var(--orange)}
    .badge-gray{background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.10);color:var(--muted)}
    .badge-purple{background:rgba(157,78,221,0.10);border:1px solid rgba(157,78,221,0.30);color:var(--purple)}

    /* ── TABLES ── */
    .tbl-wrap{overflow-x:auto;border-radius:12px;border:1px solid var(--border)}
    table.tbl{width:100%;border-collapse:collapse;font-size:12px}
    table.tbl th{padding:10px 12px;text-align:left;color:var(--muted);font-weight:600;background:rgba(255,255,255,0.02);border-bottom:1px solid var(--border);white-space:nowrap}
    table.tbl td{padding:9px 12px;border-bottom:1px solid rgba(255,255,255,0.04);vertical-align:top;word-break:break-word}
    table.tbl tr:last-child td{border-bottom:none}
    table.tbl tr:hover td{background:rgba(255,255,255,0.02)}

    /* ── KV TABLE ── */
    table.kv{width:100%;border-collapse:collapse;font-size:12px}
    table.kv td{padding:8px 10px;border-bottom:1px solid rgba(255,255,255,0.04);vertical-align:top}
    table.kv td.k{color:var(--muted);width:200px;white-space:nowrap;font-family:monospace}
    table.kv tr:last-child td{border-bottom:none}

    /* ── CONTROLS ── */
    .controls{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
    .search{flex:1;min-width:240px;background:rgba(255,255,255,0.03);border:1px solid var(--border);color:var(--txt);padding:9px 14px;border-radius:12px;outline:none;font-size:13px;transition:border-color .15s}
    .search:focus{border-color:rgba(79,255,176,0.35)}
    .search::placeholder{color:rgba(125,143,163,0.6)}
    .fbtn{cursor:pointer;border:1px solid var(--border);background:rgba(255,255,255,0.02);color:var(--muted);padding:7px 12px;border-radius:999px;font-size:12px;transition:all .15s;white-space:nowrap}
    .fbtn.active,.fbtn:hover{border-color:rgba(79,255,176,0.35);color:var(--accent);background:rgba(79,255,176,0.06)}

    /* ── ROUTE TYPE ── */
    .rt-fe{background:rgba(63,160,255,0.08);border:1px solid rgba(63,160,255,0.25);color:var(--blue);padding:3px 9px;border-radius:999px;font-size:11px}
    .rt-be{background:rgba(157,78,221,0.08);border:1px solid rgba(157,78,221,0.25);color:var(--purple);padding:3px 9px;border-radius:999px;font-size:11px}

    /* ── FIREBASE ── */
    .fb-card{background:linear-gradient(135deg,rgba(255,170,0,0.04),rgba(255,77,109,0.04));border:1px solid rgba(255,170,0,0.18);border-radius:16px;padding:18px}
    .fb-title{color:var(--orange);font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;margin-bottom:12px;display:flex;align-items:center;gap:8px}
    .fb-key{font-family:monospace;font-size:11px;color:var(--yellow);background:rgba(255,209,102,0.08);padding:2px 8px;border-radius:5px}
    .fb-val{font-family:monospace;font-size:11px;color:var(--txt);word-break:break-all}

    /* ── SERVICE GRID ── */
    .svc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px}
    .svc-tile{background:rgba(255,255,255,0.03);border:1px solid var(--border);border-radius:12px;padding:12px 14px;transition:border-color .15s}
    .svc-tile.active{border-color:rgba(79,255,176,0.30);background:rgba(79,255,176,0.04)}
    .svc-tile.inactive{opacity:.35}
    .svc-name{font-size:12px;font-weight:600;margin-top:4px;color:var(--txt)}
    .svc-dot{width:8px;height:8px;border-radius:50%;display:inline-block}
    .svc-dot.on{background:var(--accent)}
    .svc-dot.off{background:var(--border)}

    /* ── SCREENSHOT GALLERY ── */
    .gal-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}
    .tile{display:block;text-decoration:none;border:1px solid var(--border);border-radius:14px;overflow:hidden;background:rgba(255,255,255,0.02);transition:transform .12s,border-color .12s}
    .tile:hover{transform:translateY(-2px);border-color:rgba(79,255,176,0.30)}
    .tile-top{display:flex;justify-content:space-between;align-items:center;padding:9px 10px 0}
    .chip{padding:3px 9px;border-radius:999px;border:1px solid rgba(255,255,255,0.10);background:rgba(0,0,0,0.25);color:var(--txt);font-size:11px}
    .thumb{width:100%;height:175px;object-fit:cover;border-top:1px solid rgba(255,255,255,0.05);display:block}
    .tile-bot{padding:9px 10px}
    .t-url{font-size:11px;color:var(--txt);word-break:break-all}
    .t-meta{margin-top:4px;font-size:10px;color:var(--muted)}
    .t-mini{font-size:10px;color:var(--muted);word-break:break-word;margin-top:3px}

    /* ── MISC ── */
    .muted{color:var(--muted);font-size:13px}
    .sep{height:1px;background:var(--border);margin:18px 0}
    .pre{background:#050810;border:1px solid var(--border);padding:12px;border-radius:10px;overflow:auto;color:#ffd166;font-family:monospace;font-size:11px;max-height:380px;white-space:pre-wrap;word-break:break-all}
    details > summary{list-style:none;cursor:pointer}
    details > summary::-webkit-details-marker{display:none}
    footer{text-align:center;color:var(--muted);font-size:12px;padding:24px 0 12px;border-top:1px solid var(--border);margin-top:32px}
  </style>
</head>
<body>
<div class="wrap">

<script>
const RESULTS = __RESULTS_JSON__;
</script>

<script>
/* ─── helpers ─── */
function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function badge(t,cls='badge-gray'){return `<span class="badge ${cls}">${esc(t)}</span>`;}

function statusBadge(code){
  if(code==null)return badge('—');
  const n=Number(code);
  if(n>=200&&n<300)return badge(String(n),'badge-blue');
  if(n===401||n===403)return badge(String(n),'badge-orange');
  if(n>=300&&n<400)return badge(String(n),'badge-gray');
  if(n>=400)return badge(String(n),'badge-red');
  return badge(String(n),'badge-gray');
}
function accessBadge(s){
  if(s==='con acceso')return badge('✓ acceso','badge-green');
  if(s==='sin acceso')return badge('✗ bloqueado','badge-red');
  return badge(s||'—');
}
function routeTypeBadge(t){
  if(t==='backend')return '<span class="rt-be">API</span>';
  return '<span class="rt-fe">UI</span>';
}

function kvTable(obj){
  if(!obj||!Object.keys(obj).length)return '<p class="muted">—</p>';
  const rows=Object.entries(obj).map(([k,v])=>`<tr><td class="k">${esc(k)}</td><td>${esc(String(v))}</td></tr>`).join('');
  return `<table class="kv">${rows}</table>`;
}

function tbl(cols,rows,id=''){
  if(!rows||!rows.length)return '<p class="muted" style="padding:8px 0">No hay datos.</p>';
  const head=cols.map(c=>`<th>${esc(c)}</th>`).join('');
  const body=rows.map(r=>`<tr>${r.map(c=>`<td>${c}</td>`).join('')}</tr>`).join('');
  return `<div class="tbl-wrap"><table class="tbl"${id?` id="${id}"`:''}><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
}

function wireSearch(inputId,tableId,countId){
  const inp=document.getElementById(inputId);
  const tbl=document.getElementById(tableId);
  const cnt=document.getElementById(countId);
  if(!inp||!tbl)return;
  function apply(){
    const q=(inp.value||'').toLowerCase();
    let n=0;
    tbl.querySelectorAll('tbody tr').forEach(tr=>{
      const ok=!q||tr.innerText.toLowerCase().includes(q);
      tr.style.display=ok?'':'none';
      if(ok)n++;
    });
    if(cnt)cnt.textContent=String(n);
  }
  inp.addEventListener('input',apply);
  apply();
}

/* ─── main render ─── */
function build(){
  const meta=RESULTS.meta||{};
  const stats=RESULTS.stats||{};
  const stack=RESULTS.stack_summary||{};
  const tp=RESULTS.third_party_services||{};
  const fb=RESULTS.firebase||{};
  const ep=RESULTS.endpoints||{};
  const inv=RESULTS.inventory||{};
  const ts=Number(meta.timestamp||0)*1000;
  const tsStr=ts?new Date(ts).toLocaleString():'—';

  /* ── NAV ── */
  document.querySelector('.wrap').innerHTML=`
  <div class="nav">
    <div class="nav-logo">Darkm<span>Lens</span></div>
    <span class="nav-badge">v${esc(meta.tool||'DarkmLens')}</span>
    <span class="nav-right">${tsStr}</span>
  </div>

  <!-- HERO -->
  <div class="hero">
    <div>
      <div class="hero-title">Reporte de <span class="hl">Exposición Pública</span></div>
      <div class="hero-url">🎯 ${esc(RESULTS.url||'')} ${RESULTS.final_url&&RESULTS.final_url!==RESULTS.url?`→ ${esc(RESULTS.final_url)}`:''}
      </div>
      <div class="hero-meta">
        ${stack.app_type?`<span class="meta-pill">📦 Stack: <b>${esc(stack.app_type)}</b></span>`:''}
        <span class="meta-pill">🕐 <b>${tsStr}</b></span>
        <span class="meta-pill">⚠ ${esc(meta.disclaimer||'Uso autorizado únicamente.')}</span>
      </div>
    </div>
    <div class="hero-box">
      <div style="font-size:11px;color:var(--muted);margin-bottom:6px">SERVIDOR</div>
      ${kvTable(RESULTS.server_headers||{})}
    </div>
  </div>

  <!-- APP STACK -->
  ${buildStack(stack)}

  <!-- STATS -->
  <div class="stats">
    <div class="stat"><div class="stat-n">${esc(stats.assets_fetched||0)}</div><div class="stat-l">Assets JS/CSS</div></div>
    <div class="stat"><div class="stat-n">${esc(stats.maps_found||0)}</div><div class="stat-l">Sourcemaps</div></div>
    <div class="stat"><div class="stat-n">${esc(stats.pages_visited||0)}</div><div class="stat-l">Páginas visitadas</div></div>
    <div class="stat"><div class="stat-n">${(inv.routes_full_urls||[]).filter(r=>r.route_type==='frontend').length}</div><div class="stat-l">Rutas UI frontend</div></div>
    <div class="stat"><div class="stat-n">${(inv.routes_full_urls||[]).filter(r=>r.route_type==='backend').length + (ep.absolute||[]).length + (ep.relative||[]).length}</div><div class="stat-l">Endpoints API</div></div>
    <div class="stat"><div class="stat-n">${(ep.requests_inferred||[]).length}</div><div class="stat-l">Requests inferidos</div></div>
    <div class="stat"><div class="stat-n">${esc(stats.authz_routes_tested||0)}</div><div class="stat-l">AuthZ testeados</div></div>
    <div class="stat"><div class="stat-n">${esc(stats.fuzz_paths_tested||0)}</div><div class="stat-l">Fuzz paths</div></div>
    <div class="stat"><div class="stat-n">${esc(stats.fuzz_found||0)}</div><div class="stat-l">Fuzz encontrados</div></div>
    <div class="stat"><div class="stat-n">${(RESULTS.google_dorks||{}).queries?((RESULTS.google_dorks||{}).queries||[]).length:0}</div><div class="stat-l">Google Dorks</div></div>
  </div>

  <!-- TECHNOLOGIES -->
  ${buildTech()}

  <!-- SCREENSHOT PRINCIPAL -->
  ${RESULTS.screenshots&&RESULTS.screenshots.main?`
  <div class="section">
    <div class="section-h"><div class="section-title"><span class="ico ico-blue">📷</span>Captura Principal</div></div>
    <img src="${esc(RESULTS.screenshots.main)}" style="width:100%;border-radius:14px;border:1px solid var(--border)" alt="screenshot"/>
  </div>`:''}

  <!-- FIREBASE -->
  ${buildFirebase(fb)}

  <!-- THIRD PARTY SERVICES -->
  ${buildServices(tp)}

  <!-- FRONTEND ROUTES -->
  ${buildFrontendRoutes(inv)}

  <!-- BACKEND ENDPOINTS -->
  ${buildBackendEndpoints(ep,inv)}

  <!-- REQUESTS INFERRED -->
  ${buildRequests(ep)}

  <!-- AUTHZ AUDIT -->
  ${buildAuthz()}

  <!-- CONFIGS EXPUESTOS -->
  ${buildExposedConfigs()}

  <!-- v4.4: FUZZING -->
  ${buildFuzzing()}

  <!-- v4.4: GOOGLE DORKS -->
  ${buildGoogleDorks()}

  <!-- v4.4: FIREBASE PROBING -->
  ${buildFirebaseProbing()}

  <!-- SCREENSHOT GALLERY -->
  ${buildGallery()}

  <!-- NOTES -->
  ${buildNotes()}

  <!-- REACTSCAN -->
  ${buildReactScan()}

  <!-- AI EXTRACTION -->
  ${buildAiExtraction()}

  <footer>
    <b>DarkmLens</b> · Darkmoon Security Reporting · Uso autorizado únicamente
  </footer>
  `;

  /* wire searches */
  wireSearch('feSearch','feTable','feCount');
  wireSearch('beSearch','beTable','beCount');
  wireSearch('reqSearch','reqTable','reqCount');
  wireSearch('authSearch','authTable','authCount');

  wireSearch('fuzzSearch','fuzzTable','fuzzCount');
  wireSearch('dorkSearch','dorkTable','dorkCount');

  /* authz filters */
  setupAuthzFilters();

  /* gallery filter */
  setupGalleryFilter();
}

/* ─── REACTSCAN ─── */
function buildReactScan(){
  const rs=RESULTS.reactscan||{};
  if(!rs.enabled)return '';

  function rsItems(items){
    if(!items||!items.length)return '<p class="muted">Sin resultados.</p>';
    const colorMap={critical:'var(--red)',high:'var(--orange)',info:'var(--blue)',low:'var(--muted)',success:'var(--green)'};
    const labelMap={critical:'CRÍTICO',high:'ALTO',info:'INFO',low:'BAJO',success:'OK'};
    return items.map(it=>{
      const t=it.type||'info';
      const col=colorMap[t]||'var(--muted)';
      const lbl=labelMap[t]||t.toUpperCase();
      return `<div style="border-left:4px solid ${col};padding:12px 16px;margin-bottom:10px;background:rgba(255,255,255,0.02);border-radius:0 8px 8px 0;">
        <span style="background:${col};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;margin-right:10px;">${lbl}</span>
        <span style="font-size:13px;line-height:1.6;">${it.msg||''}</span>
      </div>`;
    }).join('');
  }

  const tech=rs.tech_results||[];
  const libs=rs.libs_results||[];
  const files=rs.files_results||[];
  const maps=rs.map_results||[];
  const cves=rs.cve_results||[];
  const active=rs.active_cve_results||[];

  const critCount=[...libs,...files,...maps,...cves,...active].filter(r=>r.type==='critical').length;
  const highCount=[...libs,...files,...maps,...cves,...active].filter(r=>r.type==='high').length;

  return `
  <div class="section">
    <div class="section-h">
      <div class="section-title"><span class="ico ico-red">🔬</span>ReactScan — Seguridad React/Next.js</div>
      <span class="count-badge">${critCount > 0 ? `<span style="color:var(--red);font-weight:700;">${critCount} crítico(s)</span>` : ''} ${highCount > 0 ? `· <span style="color:var(--orange);">${highCount} alto(s)</span>` : ''}</span>
    </div>

    <div class="grid2">
      <!-- Tech -->
      <div class="card">
        <div class="card-h"><h2>🛠️ Tecnologías Detectadas</h2></div>
        <div class="card-b">${rsItems(tech)}</div>
      </div>

      <!-- Sensitive Files -->
      <div class="card">
        <div class="card-h"><h2>📁 Archivos Sensibles</h2></div>
        <div class="card-b">${files.length?rsItems(files):'<p class="muted">No se encontraron archivos sensibles expuestos.</p>'}</div>
      </div>
    </div>

    <!-- Libraries & CVEs -->
    <div class="card" style="margin-top:16px;">
      <div class="card-h"><h2>📦 Librerías y Vulnerabilidades (OSV.dev)</h2></div>
      <div class="card-b">${rsItems(libs)}</div>
    </div>

    <!-- CVE Passive -->
    ${cves.length?`<div class="card" style="margin-top:16px;">
      <div class="card-h"><h2>🚨 CVEs Conocidos Next.js/React (Pasivo)</h2></div>
      <div class="card-b">${rsItems(cves)}</div>
    </div>`:''}

    <!-- Active CVE Tests -->
    ${active.length?`<div class="card" style="margin-top:16px;border-color:rgba(255,77,109,0.25);">
      <div class="card-h" style="background:rgba(255,77,109,0.04);"><h2>🧪 Verificación Activa de CVEs</h2></div>
      <div class="card-b">
        <div style="background:rgba(255,170,0,0.07);border-left:4px solid var(--orange);padding:10px 14px;border-radius:4px;margin-bottom:12px;font-size:12px;">
          ⚠️ Modo activo: pruebas confirmatorias. Solo usar en sistemas con autorización explícita.
        </div>
        ${rsItems(active)}
      </div>
    </div>`:''}

    <!-- Source Maps -->
    ${maps.length?`<div class="card" style="margin-top:16px;">
      <div class="card-h"><h2>🔍 Exposición de Código Fuente (Source Maps)</h2></div>
      <div class="card-b">${rsItems(maps)}</div>
    </div>`:''}
  </div>`;
}


/* ─── STACK ─── */
function buildStack(stack){
  if(!stack||!stack.app_type)return '';
  const fe=(stack.frontend_frameworks||[]).map(x=>`<span class="fw-badge fw-fe">⚡ ${esc(x)}</span>`).join('');
  const be=(stack.backend_frameworks||[]).map(x=>`<span class="fw-badge fw-be">⚙ ${esc(x)}</span>`).join('');
  const sv=(stack.services||[]).map(x=>`<span class="fw-badge fw-svc">☁ ${esc(x)}</span>`).join('');
  return `
  <div class="stack-card">
    <div class="stack-title">🏗 Stack Detectado</div>
    <div class="stack-type">${esc(stack.app_type)}</div>
    <div class="stack-cols">
      <div><div class="stack-col-label">Frontend</div>${fe||'<span style="color:var(--muted);font-size:12px">No identificado</span>'}</div>
      <div><div class="stack-col-label">Backend</div>${be||'<span style="color:var(--muted);font-size:12px">No identificado</span>'}</div>
      <div><div class="stack-col-label">Servicios</div>${sv||'<span style="color:var(--muted);font-size:12px">Ninguno detectado</span>'}</div>
    </div>
  </div>`;
}

/* ─── TECH ─── */
function buildTech(){
  const fp=RESULTS.fingerprints||[];
  const bk=RESULTS.backend_hints||[];
  const fw=RESULTS.framework_hints||[];
  const tc=RESULTS.technologies||[];
  if(!fp.length&&!bk.length&&!fw.length&&!tc.length)return '';
  return `
  <div class="section">
    <div class="section-h"><div class="section-title"><span class="ico ico-accent">🔍</span>Tecnologías y Fingerprints</div></div>
    <div class="grid2">
      ${fw.length||tc.length?`<div class="card"><div class="card-h"><h2>Frameworks / Wappalyzer</h2></div><div class="card-b">
        <div class="badges">${[...fw,...tc].map(x=>badge(x,'badge-blue')).join('')}</div></div></div>`:''}
      ${bk.length?`<div class="card"><div class="card-h"><h2>Backend Hints</h2></div><div class="card-b">
        <div class="badges">${bk.map(x=>badge(x,'badge-purple')).join('')}</div></div></div>`:''}
      ${fp.length?`<div class="card"><div class="card-h"><h2>Fingerprints</h2></div><div class="card-b">
        <div class="badges">${fp.map(x=>badge(x,'badge-gray')).join('')}</div></div></div>`:''}
    </div>
  </div>`;
}

/* ─── FIREBASE ─── */
function buildFirebase(fb){
  if(!fb||!fb.detected)return '';
  const parsed=(fb.configs_parsed||[]);
  const cols=(fb.collections_probable||[]);
  const rtdb=(fb.rtdb||[]);
  const frest=(fb.firestore_rest||[]);

  let configHtml='';
  if(parsed.length){
    const first=parsed[0].fields||{};
    const rows=Object.entries(first).map(([k,v])=>`<tr><td class="k"><span class="fb-key">${esc(k)}</span></td><td><span class="fb-val">${esc(v)}</span></td></tr>`).join('');
    configHtml=`<div class="sep"></div><div style="font-size:11px;color:var(--muted);margin-bottom:8px;font-weight:600;text-transform:uppercase">Configuración Firebase</div><table class="kv">${rows}</table>
    ${parsed.length>1?`<p class="muted" style="margin-top:8px">+${parsed.length-1} config(s) adicional(es).</p>`:''}`;
  }else if(fb.configs&&fb.configs.length){
    configHtml=`<div class="sep"></div><div class="pre">${esc((fb.configs[0].blob||'').slice(0,800))}</div>`;
  }

  const hints=(fb.hints||[]);
  let hintsHtml='';
  if(hints.length && !parsed.length && !(fb.configs&&fb.configs.length)){
    hintsHtml=`<div class="sep"></div><div style="font-size:11px;color:var(--muted);margin-bottom:8px;font-weight:600;text-transform:uppercase">Evidencia de Firebase (Referencias en código)</div>
    <ul style="font-size:12px;margin-left:14px;color:var(--orange)">
      ${hints.slice(0,10).map(h=>`<li>Encontrado <code>${esc(h.match)}</code> en <span class="t-mini">${esc(h.found_in)}</span></li>`).join('')}
    </ul>`;
  }

  let colsHtml='';
  if(cols.length){
    const rows2=cols.map(c=>[
      `<b>${esc(c.name||'')}</b>`,
      badge(c.evidence||'collection()','badge-orange'),
      `<span class="t-mini">${esc(c.found_in||'')}</span>`
    ]);
    colsHtml=`<div class="sep"></div><div style="font-size:11px;color:var(--muted);margin-bottom:8px;font-weight:600;text-transform:uppercase">Colecciones / Paths detectados</div>
    ${tbl(['Colección','Evidencia','Encontrado en'],rows2)}`;
  }

  return `
  <div class="section">
    <div class="section-h">
      <div class="section-title"><span class="ico ico-orange">🔥</span>Firebase</div>
      <span class="count-badge">${cols.length} colecciones · ${parsed.length} configs</span>
    </div>
    <div class="fb-card">
      <div class="fb-title">🔥 Firebase detectado</div>
      ${hintsHtml}
      ${configHtml}
      ${colsHtml}
      ${rtdb.length?`<div class="sep"></div><div style="font-size:11px;color:var(--muted);margin-bottom:8px;font-weight:600;text-transform:uppercase">Realtime DB</div><ul style="font-size:12px">${rtdb.slice(0,10).map(r=>`<li><a href="${esc(r.url||'')}" target="_blank">${esc(r.url||'')}</a></li>`).join('')}</ul>`:''}
      ${frest.length?`<div class="sep"></div><div style="font-size:11px;color:var(--muted);margin-bottom:8px;font-weight:600;text-transform:uppercase">Firestore REST</div><ul style="font-size:12px">${frest.slice(0,10).map(r=>`<li><a href="${esc(r.url||'')}" target="_blank">${esc(r.url||'')}</a></li>`).join('')}</ul>`:''}
    </div>
  </div>`;
}

/* ─── THIRD-PARTY SERVICES ─── */
function buildServices(tp){
  const services=[
    {key:'supabase',label:'Supabase',ico:'🗄'},
    {key:'auth0',label:'Auth0',ico:'🔐'},
    {key:'clerk',label:'Clerk',ico:'🔑'},
    {key:'stripe',label:'Stripe',ico:'💳'},
    {key:'mixpanel',label:'Mixpanel',ico:'📊'},
    {key:'intercom',label:'Intercom',ico:'💬'},
    {key:'pusher',label:'Pusher',ico:'📡'},
    {key:'algolia',label:'Algolia',ico:'🔎'},
    {key:'google_maps',label:'Google Maps',ico:'🗺'},
    {key:'mapbox',label:'Mapbox',ico:'📍'},
    {key:'twilio',label:'Twilio',ico:'📞'},
    {key:'onesignal',label:'OneSignal',ico:'🔔'},
    {key:'recaptcha',label:'reCAPTCHA',ico:'🤖'},
    {key:'hotjar',label:'Hotjar',ico:'🌡'},
    {key:'datadog',label:'DataDog',ico:'🐕'},
    {key:'launchdarkly',label:'LaunchDarkly',ico:'🚩'},
    {key:'amplitude',label:'Amplitude',ico:'📈'},
    {key:'posthog',label:'PostHog',ico:'🦔'},
  ];
  const detected=services.filter(s=>(tp[s.key]||{}).detected);
  const notDetected=services.filter(s=>!(tp[s.key]||{}).detected);

  let detailHtml='';
  const sup=tp.supabase||{};
  if(sup.detected){
    detailHtml+=`<div class="sep"></div><b>Supabase</b><br>
    ${sup.urls.length?`<div class="muted" style="margin-top:4px">URL: ${sup.urls.map(u=>`<a href="${esc(u)}" target="_blank">${esc(u)}</a>`).join(', ')}</div>`:''}
    ${sup.tables.length?`<div class="muted" style="margin-top:4px">Tablas detectadas: ${sup.tables.map(t=>badge(t,'badge-orange')).join('')}</div>`:''}`;
  }
  const auth=tp.auth0||{};
  if(auth.detected&&auth.domains.length){
    detailHtml+=`<div class="sep"></div><b>Auth0 domains:</b> ${auth.domains.map(d=>badge(d,'badge-purple')).join('')}`;
  }
  const stripe=tp.stripe||{};
  if(stripe.detected&&stripe.public_keys.length){
    detailHtml+=`<div class="sep"></div><b>Stripe public keys:</b> ${stripe.public_keys.map(k=>`<code>${esc(k)}</code>`).join(' ')}`;
  }
  const mapbox=tp.mapbox||{};
  if(mapbox.detected&&mapbox.tokens.length){
    detailHtml+=`<div class="sep"></div><b>Mapbox tokens:</b> ${mapbox.tokens.map(t=>`<code>${esc(t.slice(0,32))}…</code>`).join(' ')}`;
  }

  return `
  <div class="section">
    <div class="section-h">
      <div class="section-title"><span class="ico ico-green">☁</span>Servicios de Terceros</div>
      <span class="count-badge">${detected.length} detectados</span>
    </div>
    <div class="svc-grid">
      ${detected.map(s=>`<div class="svc-tile active">${s.ico} <span class="svc-dot on"></span><div class="svc-name">${esc(s.label)}</div></div>`).join('')}
      ${notDetected.map(s=>`<div class="svc-tile inactive">${s.ico} <span class="svc-dot off"></span><div class="svc-name">${esc(s.label)}</div></div>`).join('')}
    </div>
    ${detailHtml?`<div class="card" style="margin-top:14px"><div class="card-b">${detailHtml}</div></div>`:''}
  </div>`;
}

/* ─── FRONTEND ROUTES ─── */
function buildFrontendRoutes(inv){
  const routes=(inv.routes_full_urls||[]).filter(r=>r.route_type==='frontend');
  const n=routes.length;
  if(!n)return '';
  const rows=routes.slice(0,300).map(r=>[
    `<code>${esc(r.path||'')}</code>`,
    `<a href="${esc(r.full_url||'')}" target="_blank">${esc(r.full_url||'')}</a>`,
    `<span class="t-mini">${esc(r.found_in||'')}</span>`,
    r.line!=null?`<code>${esc(r.line)}</code>`:'—'
  ]);
  return `
  <div class="section">
    <div class="section-h">
      <div class="section-title"><span class="ico ico-blue">📄</span>Rutas Frontend (UI)</div>
      <span class="count-badge">Mostrando <b id="feCount">${Math.min(n,300)}</b> de ${n}</span>
    </div>
    <div class="controls">
      <input id="feSearch" class="search" placeholder="Buscar ruta frontend..."/>
    </div>
    ${tbl(['Path','URL completa','Encontrado en','Línea'],rows,'feTable')}
  </div>`;
}

/* ─── BACKEND ENDPOINTS ─── */
function buildBackendEndpoints(ep,inv){
  const beRoutes=(inv.routes_full_urls||[]).filter(r=>r.route_type==='backend');
  const abs=ep.absolute||[];
  const rel=ep.relative||[];
  const gql=ep.graphql||[];
  const ws=ep.websocket||[];
  const bases=ep.base_urls||[];

  const rows=[];
  beRoutes.slice(0,100).forEach(r=>{
    rows.push([routeTypeBadge('backend'),`<code>${esc(r.path||'')}</code>`,
      `<a href="${esc(r.full_url||'')}" target="_blank">${esc(r.full_url||'')}</a>`,
      badge('JS route','badge-gray'),`<span class="t-mini">${esc(r.found_in||'')}</span>`]);
  });
  abs.slice(0,80).forEach(x=>{
    const ps=(x.params||[]).map(p=>badge(p,'badge-gray')).join('');
    rows.push([routeTypeBadge('backend'),'—',
      `<a href="${esc(x.url||'')}" target="_blank">${esc(x.url||'')}</a>`,
      ps||badge('—','badge-gray'),`<span class="t-mini">${esc(x.found_in||'')}</span>`]);
  });
  rel.slice(0,80).forEach(x=>{
    rows.push([routeTypeBadge('backend'),`<code>${esc(x.path||'')}</code>`,
      `<a href="${esc(x.full_url||'')}" target="_blank">${esc(x.full_url||'')}</a>`,
      badge('relative','badge-gray'),`<span class="t-mini">${esc(x.found_in||'')}</span>`]);
  });

  let extras='';
  if(gql.length) extras+=`<div style="margin-top:12px"><b>GraphQL endpoints:</b> ${gql.slice(0,5).map(x=>badge(x.url_or_path||'','badge-purple')).join('')}${gql.length>5?` +${gql.length-5}`:''}`;
  if(ws.length) extras+=`<div style="margin-top:8px"><b>WebSocket URLs:</b> ${ws.slice(0,5).map(x=>`<code>${esc(x.url||'')}</code>`).join(' ')}${ws.length>5?` +${ws.length-5}`:''}</div>`;
  if(bases.length) extras+=`<div style="margin-top:8px"><b>Base URLs detectadas:</b> ${bases.slice(0,5).map(x=>badge(x.value||'','badge-blue')).join('')}</div>`;

  const total=beRoutes.length+abs.length+rel.length;
  if(!total&&!gql.length&&!ws.length&&!bases.length)return '';
  return `
  <div class="section">
    <div class="section-h">
      <div class="section-title"><span class="ico ico-purple">⚙</span>Endpoints Backend / API</div>
      <span class="count-badge">~${total} rutas · ${gql.length} GraphQL · ${ws.length} WS</span>
    </div>
    <div class="controls">
      <input id="beSearch" class="search" placeholder="Buscar endpoint API..."/>
    </div>
    ${rows.length?tbl(['Tipo','Path','URL','Params/Tags','Encontrado en'],rows,'beTable'):''}
    ${extras}
  </div>`;
}

/* ─── REQUESTS INFERRED ─── */
function buildRequests(ep){
  const reqs=ep.requests_inferred||[];
  if(!reqs.length)return '';
  const rows=reqs.slice(0,250).map(x=>[
    badge((x.method||'?').toUpperCase(), x.method==='GET'?'badge-blue':x.method==='POST'?'badge-purple':x.method==='DELETE'?'badge-red':'badge-orange'),
    `<a href="${esc(x.full_url||'')}" target="_blank">${esc(x.full_url||x.url_or_path||'')}</a>`,
    (x.params||[]).length?(x.params||[]).map(p=>badge(p,'badge-gray')).join(''):badge('—','badge-gray'),
    (x.body_keys||[]).length?(x.body_keys||[]).map(p=>badge(p,'badge-gray')).join(''):badge('—','badge-gray'),
    `<span class="t-mini">${esc(x.evidence||'')}</span>`,
    `<span class="t-mini">${esc(x.found_in||'')}${x.line?':'+x.line:''}</span>`
  ]);
  return `
  <div class="section">
    <div class="section-h">
      <div class="section-title"><span class="ico ico-accent">📡</span>Requests Inferidos (fetch/axios)</div>
      <span class="count-badge">Mostrando <b id="reqCount">${Math.min(reqs.length,250)}</b> de ${reqs.length}</span>
    </div>
    <div class="controls">
      <input id="reqSearch" class="search" placeholder="Buscar por método, URL, params, body..."/>
    </div>
    ${tbl(['Método','URL','Query params','Body keys','Evidencia','Encontrado en'],rows,'reqTable')}
  </div>`;
}

/* ─── AUTHZ AUDIT ─── */
function buildAuthz(){
  const items=(RESULTS.authz_audit&&RESULTS.authz_audit.items)||[];
  if(!items.length)return '';
  const rows=items.map(it=>{
    const params=(it.params||[]).map(p=>badge(p,'badge-gray')).join('')||badge('—','badge-gray');
    const bkeys=(it.body_keys||[]).map(p=>badge(p,'badge-gray')).join('')||badge('—','badge-gray');
    const methods=(it.methods||['GET']).map(m=>badge(m,'badge-blue')).join('');
    return [
      `${statusBadge(it.status)} ${accessBadge(it.state)}<div class="t-mini">${esc(it.reason||'')}</div>`,
      `<a href="${esc(it.url||'')}" target="_blank">${esc(it.url||'')}</a>${it.ai_summary?`<div class="t-mini">${esc(it.ai_summary)}</div>`:''}`,
      methods,params,bkeys,
      it.screenshot?`<a href="${esc(it.screenshot)}" target="_blank">ver</a>`:'—',
    ];
  });
  return `
  <div class="section">
    <div class="section-h">
      <div class="section-title"><span class="ico ico-red">🔐</span>AuthZ Audit</div>
      <span class="count-badge">Mostrando <b id="authCount">${items.length}</b> rutas</span>
    </div>
    <div class="controls">
      <input id="authSearch" class="search" placeholder="Buscar URL, estado..."/>
      <button class="fbtn active" data-af="all">Todas</button>
      <button class="fbtn" data-af="access">Con acceso</button>
      <button class="fbtn" data-af="noaccess">Sin acceso</button>
      <button class="fbtn" data-af="401">401</button>
      <button class="fbtn" data-af="403">403</button>
      <button class="fbtn" data-af="404">404</button>
    </div>
    ${tbl(['Estado','URL','Métodos','Query params','Body keys','Screenshot'],rows,'authTable')}
  </div>`;
}

/* ─── EXPOSED CONFIGS ─── */
function buildExposedConfigs(){
  const cfg=RESULTS.exposed_configs||{};
  const sentry=cfg.sentry||[];
  const ga=cfg.google_analytics||[];
  const seg=cfg.segment||[];
  const cog=cfg.aws_amplify_cognito||[];
  const app=cfg.aws_appsync_amplify||[];
  const other=cfg.other||[];
  const total=sentry.length+ga.length+seg.length+cog.length+app.length+other.length;
  if(!total)return '';
  let html='';
  if(sentry.length) html+=`<div style="margin-bottom:10px"><b>Sentry DSN:</b> ${sentry.map(x=>`<code>${esc(x.dsn||'')}</code>`).join(' ')}</div>`;
  if(ga.length) html+=`<div style="margin-bottom:10px"><b>Google Analytics:</b> ${ga.map(x=>badge(x.id||'','badge-blue')).join('')}</div>`;
  if(seg.length) html+=`<div style="margin-bottom:10px"><b>Segment keys:</b> ${seg.map(x=>`<code>${esc(x.key||'')}</code>`).join(' ')}</div>`;
  if(cog.length) html+=`<div style="margin-bottom:10px"><b>AWS Cognito hits:</b> ${cog.slice(0,6).map(x=>badge(x.hit||'','badge-orange')).join('')}</div>`;
  if(app.length) html+=`<div style="margin-bottom:10px"><b>AWS AppSync hits:</b> ${app.slice(0,6).map(x=>badge(x.hit||'','badge-orange')).join('')}</div>`;
  if(other.length&&other[0].sourcemap) html+=`<div><b>Sourcemaps encontrados:</b> ${other.map(o=>o.sourcemap?`<code>${esc(o.sourcemap.map_url||'')}</code>`:'' ).join(' ')}</div>`;
  return `
  <div class="section">
    <div class="section-h"><div class="section-title"><span class="ico ico-orange">⚠</span>Configs Expuestas</div></div>
    <div class="card"><div class="card-b">${html}</div></div>
  </div>`;
}

/* ─── v4.4: FUZZING ─── */
function buildFuzzing(){
  const fz=RESULTS.fuzzing||{};
  const found=fz.found||[];
  const dirs=fz.dir_listings||[];
  if(!found.length&&!dirs.length)return '';
  const rows=found.slice(0,300).map(x=>[
    statusBadge(x.status),
    `<code>${esc(x.path||'')}</code>`,
    `<a href="${esc(x.url||'')}" target="_blank">${esc(x.url||'')}</a>`,
    x.dir_listing?badge('DIR LISTING','badge-red'):'—',
    `${esc(x.size||0)} b`,
    x.redirect_to?`<span class="t-mini">${esc(x.redirect_to)}</span>`:'—',
    `${esc(x.elapsed_ms||0)} ms`,
  ]);
  return `
  <div class="section">
    <div class="section-h">
      <div class="section-title"><span class="ico ico-red">🔎</span>Directory Fuzzing</div>
      <span class="count-badge">Mostrando <b id="fuzzCount">${Math.min(found.length,300)}</b> de ${found.length} · ${dirs.length} dir listings</span>
    </div>
    ${dirs.length?`<div class="card" style="margin-bottom:14px;border-color:rgba(255,77,109,0.30)"><div class="card-b" style="color:var(--red)">
      <b>⚠ Directory Listing(s) detectados:</b><ul style="font-size:12px;margin-top:6px">${dirs.map(d=>`<li><a href="${esc(d.url||'')}" target="_blank">${esc(d.path||'')}</a></li>`).join('')}</ul>
    </div></div>`:''}
    <div class="controls">
      <input id="fuzzSearch" class="search" placeholder="Buscar path, status..."/>
    </div>
    ${tbl(['Status','Path','URL','Dir Listing','Size','Redirect','Tiempo'],rows,'fuzzTable')}
  </div>`;
}

/* ─── v4.4: GOOGLE DORKS ─── */
function buildGoogleDorks(){
  const gd=RESULTS.google_dorks||{};
  const queries=gd.queries||[];
  if(!queries.length)return '';
  const ipBlocked = gd.ip_blocked === true;

  const rows=queries.map(q=>{
    let fStatus = '';
    if(q.found === true){
       fStatus = '<span style="color:var(--green);font-weight:bold;">[+] Encontrado</span>';
    } else if(q.found === false){
       fStatus = '<span style="color:var(--muted);">[-] Sin resultados</span>';
    } else if(q.found === 'blocked'){
       fStatus = '<span style="color:var(--red);font-weight:bold;">🚫 IP Bloqueada</span>';
    } else if(q.found === 'skipped'){
       fStatus = '<span style="color:var(--muted);font-style:italic;">⏭ Omitida (IP bloqueada)</span>';
    } else {
       fStatus = '<span style="color:var(--orange);">[!] Error</span>';
    }
    return [
      badge(q.category||'','badge-purple'),
      `<code style="font-size:11px;">${esc(q.dork||'')}</code>`,
      esc(q.description||''),
      fStatus,
      `<a href="${esc(q.google_url||'')}" target="_blank" rel="noopener" style="white-space:nowrap;">🔗 Buscar aquí</a>`,
    ];
  });

  const foundCount = queries.filter(q => q.found === true).length;
  const blockedCount = queries.filter(q => q.found === 'blocked').length;
  const skippedCount = queries.filter(q => q.found === 'skipped').length;

  const ipBlockBanner = ipBlocked ? `
    <div style="background:rgba(255,77,109,0.10);border:1px solid rgba(255,77,109,0.35);border-radius:12px;padding:14px 18px;margin-bottom:16px;display:flex;align-items:flex-start;gap:12px;">
      <span style="font-size:22px;flex-shrink:0;">🚫</span>
      <div>
        <b style="color:var(--red);font-size:14px;">IP Bloqueada por Google — Búsqueda Automática Detenida</b>
        <p style="color:var(--muted);font-size:12px;margin-top:4px;">
          Google bloqueó la IP tras ${blockedCount} intento(s) consecutivos. Se omitieron ${skippedCount} dork(s) restantes.
          <br>Usa los enlaces <b>🔗 Buscar aquí</b> de la tabla para ejecutar cada búsqueda manualmente desde tu navegador.
        </p>
      </div>
    </div>` : '';

  return `
  <div class="section">
    <div class="section-h">
      <div class="section-title"><span class="ico ico-green">🌐</span>Google Dorks${ipBlocked?' <span style="color:var(--red);font-size:12px;">(⚠ IP bloqueada)</span>':''}</div>
      <span class="count-badge">
        <b id="dorkCount">${queries.length}</b> queries ·
        <span style="color:var(--green);font-weight:bold;">${foundCount} con resultados</span>
        ${blockedCount?`· <span style="color:var(--red);">${blockedCount} bloqueadas</span>`:''}
        ${skippedCount?`· <span style="color:var(--muted);">${skippedCount} omitidas</span>`:''}
        · Dominio: <b>${esc(gd.domain||'')}</b>
      </span>
    </div>
    ${ipBlockBanner}
    <div class="controls">
      <input id="dorkSearch" class="search" placeholder="Buscar dork, categoría..."/>
    </div>
    ${tbl(['Categoría','Dork Query','Descripción','Estado','Enlace Manual'],rows,'dorkTable')}
    <div class="muted" style="margin-top:8px">💡 Haz clic en <b>🔗 Buscar aquí</b> para abrir cada dork en Google. Los enlaces funcionan aunque la búsqueda automática haya sido bloqueada.</div>
  </div>`;
}

/* ─── v4.4: FIREBASE PROBING ─── */
function buildFirebaseProbing(){
  const fp=RESULTS.firebase_probing||{};
  const rtdb=fp.rtdb_open||[];
  const fs=fp.firestore_open||[];
  const st=fp.storage_open||[];
  const openRtdb=rtdb.filter(x=>x.open);
  const openFs=fs.filter(x=>x.open);
  const openSt=st.filter(x=>x.open);
  if(!rtdb.length&&!fs.length&&!st.length)return '';

  let html='';
  if(openRtdb.length){
    html+=`<div class="sep"></div><div style="font-size:11px;color:var(--red);margin-bottom:8px;font-weight:600;text-transform:uppercase">⚠ RTDB ABIERTO</div>`;
    openRtdb.forEach(r=>{
      html+=`<div style="margin-bottom:8px"><a href="${esc(r.url||'')}" target="_blank">${esc(r.url||'')}</a>
      ${(r.keys_sample||[]).length?`<div class="muted">Keys: ${(r.keys_sample||[]).map(k=>badge(k,'badge-orange')).join('')}</div>`:''}</div>`;
    });
  }
  if(openFs.length){
    html+=`<div class="sep"></div><div style="font-size:11px;color:var(--red);margin-bottom:8px;font-weight:600;text-transform:uppercase">⚠ Firestore ABIERTO</div>`;
    openFs.forEach(r=>{
      html+=`<div style="margin-bottom:8px"><b>${esc(r.collection||'')}</b> @ ${esc(r.project||'')}
      <div class="muted">${esc(r.docs_returned||0)} doc(s) devueltos · <a href="${esc(r.url||'')}" target="_blank">ver</a></div></div>`;
    });
  }
  if(openSt.length){
    html+=`<div class="sep"></div><div style="font-size:11px;color:var(--red);margin-bottom:8px;font-weight:600;text-transform:uppercase">⚠ Storage ABIERTO</div>`;
    openSt.forEach(r=>{
      html+=`<div style="margin-bottom:8px"><b>${esc(r.bucket||'')}</b>
      ${(r.files_sample||[]).length?`<div class="muted">Archivos: ${(r.files_sample||[]).map(f=>badge(f,'badge-orange')).join('')}</div>`:''}
      <div class="muted"><a href="${esc(r.url||'')}" target="_blank">ver</a></div></div>`;
    });
  }

  // Closed probes summary
  const closedRtdb=rtdb.filter(x=>!x.open);
  const closedFs=fs.filter(x=>!x.open);
  const closedSt=st.filter(x=>!x.open);
  if(closedRtdb.length||closedFs.length||closedSt.length){
    html+=`<div class="sep"></div><div style="font-size:11px;color:var(--muted);margin-bottom:8px;font-weight:600;text-transform:uppercase">Protegidos (acceso denegado)</div>`;
    if(closedRtdb.length) html+=`<div class="muted">RTDB: ${closedRtdb.length} endpoint(s) protegidos</div>`;
    if(closedFs.length) html+=`<div class="muted">Firestore: ${closedFs.length} colección(es) protegida(s)</div>`;
    if(closedSt.length) html+=`<div class="muted">Storage: ${closedSt.length} bucket(s) protegido(s)</div>`;
  }

  const totalOpen=openRtdb.length+openFs.length+openSt.length;
  return `
  <div class="section">
    <div class="section-h">
      <div class="section-title"><span class="ico ico-red">🔥</span>Firebase Probing</div>
      <span class="count-badge">${totalOpen} abierto(s) · ${rtdb.length+fs.length+st.length} probados</span>
    </div>
    <div class="fb-card">
      <div class="fb-title">${totalOpen?'⚠ Acceso abierto detectado':'✓ Sin acceso abierto'}</div>
      ${html}
    </div>
  </div>`;
}

/* ─── GALLERY ─── */
function buildGallery(){
  const shots=(RESULTS.screenshots&&RESULTS.screenshots.routes)||[];
  if(!shots.length)return '';
  const tiles=shots.map(it=>`
    <a class="tile" href="${esc(it.path||'')}" target="_blank" data-url="${esc(it.url||'')}">
      <div class="tile-top"><span class="chip">${esc(it.kind||'route')}</span></div>
      <img class="thumb" src="${esc(it.path||'')}" alt=""/>
      <div class="tile-bot"><div class="t-url">${esc(it.url||'')}</div></div>
    </a>`).join('');
  return `
  <div class="section">
    <div class="section-h">
      <div class="section-title"><span class="ico ico-blue">🖼</span>Galería Screenshots</div>
      <span class="count-badge" id="galCount">${shots.length} capturas</span>
    </div>
    <div class="controls"><input id="galSearch" class="search" placeholder="Filtrar por URL..."/></div>
    <div class="gal-grid" id="galGrid">${tiles}</div>
  </div>`;
}

/* ─── NOTES ─── */
function buildNotes(){
  const notes=RESULTS.notes||[];
  if(!notes.length)return '';
  return `
  <div class="section">
    <div class="section-h"><div class="section-title"><span class="ico ico-accent">📝</span>Notas del Escaneo</div></div>
    <div class="card"><div class="card-b"><ul style="font-size:12px;padding-left:18px">${notes.slice(0,120).map(n=>`<li>${esc(n)}</li>`).join('')}</ul></div></div>
  </div>`;
}

/* ─── AUTHZ FILTER LOGIC ─── */
function setupAuthzFilters(){
  const authTable=document.getElementById('authTable');
  const authSearch=document.getElementById('authSearch');
  const authCount=document.getElementById('authCount');
  let active='all';
  function apply(){
    if(!authTable)return;
    const q=(authSearch?authSearch.value:'').toLowerCase();
    let n=0;
    authTable.querySelectorAll('tbody tr').forEach(tr=>{
      const txt=tr.innerText.toLowerCase();
      const okF=active==='all'||(active==='access'&&txt.includes('acceso')&&!txt.includes('bloqueado'))||(active==='noaccess'&&txt.includes('bloqueado'))||(active==='401'&&txt.includes('401'))||(active==='403'&&txt.includes('403'))||(active==='404'&&txt.includes('404'));
      const okS=!q||txt.includes(q);
      tr.style.display=(okF&&okS)?'':'none';
      if(okF&&okS)n++;
    });
    if(authCount)authCount.textContent=String(n);
  }
  document.querySelectorAll('[data-af]').forEach(b=>{
    b.addEventListener('click',()=>{
      document.querySelectorAll('[data-af]').forEach(x=>x.classList.remove('active'));
      b.classList.add('active');
      active=b.getAttribute('data-af');
      apply();
    });
  });
  if(authSearch)authSearch.addEventListener('input',apply);
  apply();
}

/* ─── GALLERY FILTER ─── */
function setupGalleryFilter(){
  const galGrid=document.getElementById('galGrid');
  const galSearch=document.getElementById('galSearch');
  const galCount=document.getElementById('galCount');
  if(!galSearch||!galGrid)return;
  function apply(){
    const q=galSearch.value.toLowerCase();
    let n=0;
    galGrid.querySelectorAll('.tile').forEach(t=>{
      const ok=!q||(t.getAttribute('data-url')||'').toLowerCase().includes(q);
      t.style.display=ok?'':'none';
      if(ok)n++;
    });
    if(galCount)galCount.textContent=String(n)+' capturas';
  }
  galSearch.addEventListener('input',apply);
}

/* ─── AI EXTRACTION ─── */
function buildAiExtraction(){
  const ai=RESULTS.ai_extraction||{};
  if((!ai.api_calls || !ai.api_calls.length) && (!ai.other_findings || !ai.other_findings.length) && (!ai.base_urls || !ai.base_urls.length)) return '';
  let html = `<div class="section"><div class="section-h"><div class="section-title"><span class="ico ico-purple">🤖</span>Análisis IA del Backend (Claude/Ollama/LM Studio)</div></div>`;
  if(ai.backend_structure) {
    html += `<div class="card" style="margin-bottom:16px"><div class="card-b"><p><strong>Estructura y Clasificación:</strong> ${esc(ai.backend_structure)}</p></div></div>`;
  }
  if(ai.base_urls && ai.base_urls.length) {
    const cols0 = ['URL Base','Descripción', 'Archivo Origen'];
    const rows0 = ai.base_urls.map(b => [
      `<code style="color:var(--green);font-weight:bold;">${esc(b.url)}</code>`,
      esc(b.description||''),
      esc(b.source_file||'')
    ]);
    html += '<h3 style="margin-bottom:8px;font-size:14px;color:var(--green);">URLs de Backend Descubiertas</h3><div class="card" style="margin-bottom:16px"><div class="card-b">' + tbl(cols0, rows0, 'aiBaseUrlsTable') + '</div></div>';
  }
  if(ai.firebase_config_reconstructed) {
    html += `<h3 style="margin-bottom:8px;font-size:14px;color:var(--orange);">Conexión a Firebase Detectada</h3><div class="card" style="margin-bottom:16px"><div class="card-b"><pre style="margin:0;font-size:13px;color:var(--accent);"><code>${esc(ai.firebase_config_reconstructed)}</code></pre></div></div>`;
  }
  if(ai.api_calls && ai.api_calls.length) {
    const cols = ['URL / Ruta','Método','Payload / Parámetros','Ejemplo de Petición'];
        const rows = ai.api_calls
            .filter(api => api && (api.url || api.method || api.payload || api.sample_request))
            .map(api => [
                `<code style="white-space:pre-wrap;display:block;max-width:320px;overflow-x:auto;">${esc(api.url||'—')}</code>`,
                badge(api.method||'—', api.method ? 'badge-blue' : 'badge-gray'),
                `<code style="white-space:pre-wrap;display:block;max-width:300px;overflow-x:auto;">${esc(api.payload||'—')}</code>`,
                `<code style="white-space:pre-wrap;display:block;max-width:300px;overflow-x:auto;">${esc(api.sample_request||'—')}</code>`
            ]);
    html += '<h3 style="margin-bottom:8px;font-size:14px;color:var(--accent);">Llamadas a API Extraídas</h3><div class="card" style="margin-bottom:16px"><div class="card-b">' + tbl(cols, rows, 'aiTable') + '</div></div>';
  }
  if(ai.other_findings && ai.other_findings.length) {
        const cols2 = ['Tipo','Valor / Endpoint','Detalle / Fuente'];
        const rows2 = ai.other_findings
            .filter(f => f && (f.type || f.endpoint || f.value || f.name || f.config || f.description || f.method))
            .map(f => {
                const typeLabel = f.type || (f.endpoint ? 'Endpoint' : f.name ? 'Key' : f.method ? 'API' : 'Hallazgo');
                const valueLabel = f.value || f.endpoint || f.name || f.config || '—';
                const detailParts = [];
                if (f.method) detailParts.push(`Method: ${f.method}`);
                if (f.description) detailParts.push(f.description);
                if (f.config && f.config !== valueLabel) detailParts.push(`Config: ${f.config}`);
                if (f.source_file) detailParts.push(`Source: ${f.source_file}`);
                return [
                    badge(typeLabel,'badge-orange'),
                    `<code style="white-space:pre-wrap;display:block;max-width:400px;overflow-x:auto;color:var(--yellow);">${esc(valueLabel)}</code>`,
                    esc(detailParts.join(' · ') || '—')
                ];
            });
    html += '<h3 style="margin-bottom:8px;font-size:14px;color:var(--orange);">Otros Hallazgos (Keys, Firebase, etc)</h3><div class="card fb-card" style="margin-bottom:16px"><div class="card-b">' + tbl(cols2, rows2, 'aiOthersTable') + '</div></div>';
  }
  html += `</div>`;
  return html;
}

build();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
