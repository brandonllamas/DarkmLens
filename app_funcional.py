#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import re
import json
import time
import argparse
import warnings
from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Any
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup
from colorama import Fore, init

# Wappalyzer (opcional)
try:
    from Wappalyzer import Wappalyzer, WebPage  # type: ignore
    HAS_WAPPALYZER = True
except Exception:
    HAS_WAPPALYZER = False

init(autoreset=True)


# -----------------------------
# Utils
# -----------------------------
def same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)

def uniq_list(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out

def safe_mkdir(path: str):
    os.makedirs(path, exist_ok=True)

def line_number_from_index(text: str, idx: int) -> int:
    return text.count("\n", 0, max(0, idx)) + 1

def html_escape(s: str) -> str:
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&#39;"))

def summarize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    keep = [
        "server", "via", "x-cache", "x-powered-by",
        "x-amz-cf-id", "x-amz-cf-pop",
        "content-security-policy", "strict-transport-security",
        "x-frame-options", "x-content-type-options",
        "referrer-policy", "permissions-policy",
        "set-cookie",
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

def is_truthy_list(x) -> bool:
    return isinstance(x, list) and len(x) > 0


@dataclass
class FetchResult:
    url: str
    status: int
    content_type: str
    text: str
    headers: Dict[str, str]


class DarkmLens:
    """
    DarkmLens v3.2 (Darkmoon)
    - Análisis pasivo (OSINT defensivo) de exposición pública.
    - Extrae: tech hints, rutas, endpoints, requests inferidos (método), configs expuestas,
      Next.js info, sourcemaps (mismo origen), screenshot opcional.
    """

    # URLs absolutas (incluye query)
    ABS_URL_RE = re.compile(r'https?://[^\s"\'<>]+(?:\?[^\s"\'<>]+)?', re.IGNORECASE)

    # Endpoints relativos “comunes”
    REL_ENDPOINT_RE = re.compile(r'["\'](\/(?:api|graphql|gql|auth|oauth|v\d+|rest)\/[^"\']+)["\']', re.IGNORECASE)
    GRAPHQL_HINT_RE = re.compile(r'\/graphql\b|\/gql\b', re.IGNORECASE)
    WS_RE = re.compile(r'\b(wss?:\/\/[^\s"\'<>]+)', re.IGNORECASE)

    # Rutas candidatas en JS/CSS
    ROUTE_RE = re.compile(r'["\'](\/[^"\']{1,220})["\']')

    # Assets comunes (para filtrar rutas “que son archivos”)
    ASSET_EXT_RE = re.compile(r".*\.(png|jpg|jpeg|gif|webp|svg|ico|css|js|map|woff2?|ttf|eot)(\?.*)?$", re.IGNORECASE)

    # Sourcemap
    SOURCEMAP_RE = re.compile(r"sourceMappingURL\s*=\s*([^\s]+)")

    # Base URLs
    BASEURL_RE = re.compile(r'(baseURL|BASE_URL|API_URL|NEXT_PUBLIC_API_URL)\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE)

    # Observabilidad / analytics
    SENTRY_RE = re.compile(r'https:\/\/[a-z0-9]+@o\d+\.ingest\.sentry\.io\/\d+', re.IGNORECASE)
    GA_RE = re.compile(r'\bG-[A-Z0-9]{8,}\b|\bUA-\d{4,}-\d+\b', re.IGNORECASE)
    SEGMENT_RE = re.compile(r'analytics\.load\(["\']([a-z0-9]{10,})["\']\)', re.IGNORECASE)

    # AWS Amplify/Cognito/AppSync hints
    COGNITO_RE = re.compile(r'\b(userPoolId|userPoolWebClientId|identityPoolId|aws_project_region|cognito-idp\.[a-z0-9-]+\.amazonaws\.com)\b', re.IGNORECASE)
    APPSYNC_RE = re.compile(r'\b(appSyncGraphqlEndpoint|aws_appsync_graphqlEndpoint|aws_appsync_authenticationType|AWSAppSync)\b', re.IGNORECASE)

    # Firebase (estricto) + hint
    FIREBASE_HINT_RE = re.compile(r'firebaseapp\.com|firebaseio\.com|gstatic\.com/firebasejs|firebase', re.IGNORECASE)
    FIREBASE_STRICT_RE = re.compile(
        r'({[^{}]{0,800}'
        r'(apiKey\s*[:=]\s*["\'][^"\']+["\'])'
        r'[^{}]{0,800}'
        r'(authDomain\s*[:=]\s*["\'][^"\']+["\'])'
        r'[^{}]{0,800}'
        r'(projectId\s*[:=]\s*["\'][^"\']+["\'])'
        r'[^{}]{0,800}'
        r'(storageBucket|messagingSenderId|appId)'
        r'[^{}]{0,800}})',
        re.IGNORECASE
    )

    # Filtro rutas “basura”
    BAD_ROUTE_CHARS_RE = re.compile(r'[<>"\'{}\(\)\*\$,]|\\n|\\r|\\t')
    BAD_ROUTE_PATTERNS_RE = re.compile(r'\/\(\.\+\?\)|\(\.\+\?\)|\[\^\/\]\+\?\)|\(\[\^\/\]\+\?\)|\/\.\*|\/\.\+|\(\?:|\|\|', re.IGNORECASE)

    # Inferencia de requests (fetch/axios)
    FETCH_CALL_RE = re.compile(
        r'\bfetch\s*\(\s*(?P<q>["\'])(?P<url>[^"\']+)(?P=q)\s*(?:,\s*(?P<opts>\{.*?\}))?\s*\)',
        re.IGNORECASE | re.DOTALL
    )
    FETCH_METHOD_RE = re.compile(r'\bmethod\s*:\s*(?P<q>["\'])(?P<m>[A-Z]+)(?P=q)', re.IGNORECASE)

    AXIOS_SHORT_RE = re.compile(
        r'\baxios\.(get|post|put|patch|delete)\s*\(\s*(?P<q>["\'])(?P<url>[^"\']+)(?P=q)',
        re.IGNORECASE
    )
    AXIOS_OBJ_RE = re.compile(r'\baxios\s*\(\s*(?P<obj>\{.*?\})\s*\)', re.IGNORECASE | re.DOTALL)
    AXIOS_URL_IN_OBJ_RE = re.compile(r'\burl\s*:\s*(?P<q>["\'])(?P<url>[^"\']+)(?P=q)', re.IGNORECASE)
    AXIOS_METHOD_IN_OBJ_RE = re.compile(r'\bmethod\s*:\s*(?P<q>["\'])(?P<m>[a-z]+)(?P=q)', re.IGNORECASE)
    AXIOS_PARAMS_IN_OBJ_RE = re.compile(r'\bparams\s*:\s*\{(?P<p>.*?)\}', re.IGNORECASE | re.DOTALL)

    def __init__(
        self,
        target_url: str,
        out_dir: str = "out",
        max_assets: int = 120,
        max_map_files: int = 20,
        request_timeout: int = 15,
        sleep_between: float = 0.03,
        screenshot: bool = True,
    ):
        self.target_url = target_url
        self.out_dir = out_dir
        self.max_assets = max_assets
        self.max_map_files = max_map_files
        self.request_timeout = request_timeout
        self.sleep_between = sleep_between
        self.enable_screenshot = screenshot

        safe_mkdir(self.out_dir)

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/122.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })

        self.results: Dict[str, Any] = {
            "meta": {
                "tool": "DarkmLens v3.2 (Darkmoon)",
                "purpose": "Defensive passive analysis (public exposure review)",
                "disclaimer": "Use only on assets you own or have explicit authorization to test.",
                "timestamp": int(time.time()),
            },
            "url": target_url,
            "final_url": "",
            "screenshot": None,
            "server_headers": {},
            "technologies": [],
            "fingerprints": [],
            "backend_hints": [],
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
            "endpoints": {
                "absolute": [],
                "relative": [],
                "graphql": [],
                "websocket": [],
                "base_urls": [],
                "requests_inferred": [],
            },
            "exposed_configs": {
                "firebase": [],
                "aws_amplify_cognito": [],
                "aws_appsync_amplify": [],
                "sentry": [],
                "google_analytics": [],
                "segment": [],
                "other": [],
            },
            "notes": [],
            "stats": {"assets_fetched": 0, "maps_found": 0, "maps_fetched": 0}
        }

    # -----------------------------
    # UI
    # -----------------------------
    def print_banner(self):
        print(f"{Fore.CYAN}========================================")
        print(f"{Fore.MAGENTA}   DarkmLens v3.2  |  Darkmoon")
        print(f"{Fore.CYAN}========================================")
        print(f"{Fore.YELLOW}Uso autorizado únicamente. Análisis pasivo.\n")

    # -----------------------------
    # Network
    # -----------------------------
    def fetch(self, url: str) -> Optional[FetchResult]:
        try:
            r = self.session.get(url, timeout=self.request_timeout, allow_redirects=True)
            ct = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            return FetchResult(url=r.url, status=r.status_code, content_type=ct, text=r.text or "", headers=dict(r.headers))
        except Exception as e:
            self.results["notes"].append(f"Fetch error {url}: {e}")
            return None

    # -----------------------------
    # Detection
    # -----------------------------
    def identify_tech_wappalyzer(self):
        if not HAS_WAPPALYZER:
            self.results["notes"].append("Wappalyzer no instalado (opcional).")
            return
        print(f"[*] Identificando tecnologías (Wappalyzer) en {self.target_url}...")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                wappalyzer = Wappalyzer.latest()
                webpage = WebPage.new_from_url(self.target_url)
                techs = list(wappalyzer.analyze(webpage))
                self.results["technologies"].extend(techs)
        except Exception as e:
            self.results["notes"].append(f"Wappalyzer error: {e}")

    def fingerprint_html_and_headers(self, html: str, headers: Dict[str, str]):
        fp: List[str] = []
        backend: List[str] = []

        if "/_next/static/" in html or 'id="__NEXT_DATA__"' in html:
            fp.append("Next.js (heurístico)")
            self.results["nextjs"]["detected"] = True

        if "data-reactroot" in html or "react" in html.lower():
            fp.append("React (heurístico)")

        if "data-emotion" in html or "Mui" in html:
            fp.append("MUI/Emotion (heurístico)")

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

        self.results["fingerprints"].extend(fp)
        self.results["backend_hints"].extend(backend)

    # -----------------------------
    # Findings helpers
    # -----------------------------
    def add_finding(self, bucket: List[dict], data: dict):
        bucket.append(data)

    def looks_like_real_route(self, p: str) -> bool:
        if not p or not p.startswith("/"):
            return False
        if len(p) < 2 or len(p) > 140:
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

    # -----------------------------
    # Requests inference
    # -----------------------------
    def infer_requests_from_text(self, text: str, base: str, source_name: str):
        # fetch("url", { method: "POST" ... })
        for m in self.FETCH_CALL_RE.finditer(text):
            url = m.group("url")
            opts = m.group("opts") or ""
            ln = line_number_from_index(text, m.start())

            method = "GET"
            mm = self.FETCH_METHOD_RE.search(opts)
            if mm:
                method = mm.group("m").upper()

            full = urljoin(base, url) if url.startswith("/") else url
            self.add_finding(self.results["endpoints"]["requests_inferred"], {
                "method": method,
                "url_or_path": url,
                "full_url": full,
                "params": extract_query_params(full),
                "found_in": source_name,
                "line": ln,
                "evidence": "fetch(...)",
            })

        # axios.get/post/put/delete(...)
        for m in self.AXIOS_SHORT_RE.finditer(text):
            meth = m.group(1).upper()
            url = m.group("url")
            ln = line_number_from_index(text, m.start())
            full = urljoin(base, url) if url.startswith("/") else url
            self.add_finding(self.results["endpoints"]["requests_inferred"], {
                "method": meth,
                "url_or_path": url,
                "full_url": full,
                "params": extract_query_params(full),
                "found_in": source_name,
                "line": ln,
                "evidence": f"axios.{meth.lower()}(...)",
            })

        # axios({ url, method, params })
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
                keys = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*:', mp.group("p")[:1200])
                for k in keys:
                    if k not in params:
                        params.append(k)
                params = sorted(set(params))

            self.add_finding(self.results["endpoints"]["requests_inferred"], {
                "method": method,
                "url_or_path": url,
                "full_url": full,
                "params": params,
                "found_in": source_name,
                "line": ln,
                "evidence": "axios({ ... })",
            })

    # -----------------------------
    # Extractors
    # -----------------------------
    def extract_routes_from_dom(self, soup: BeautifulSoup, base: str):
        def add_dom_url(raw: str, tag: str):
            if not raw:
                return
            raw = raw.strip()
            if raw.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
                return
            u = urljoin(base, raw)
            if not same_origin(u, base):
                return
            path = urlparse(u).path or "/"
            self.add_finding(self.results["inventory"]["routes_full_urls"], {
                "path": path,
                "full_url": u,
                "found_in": f"DOM:{tag} @ {base}",
                "line": None
            })

        for a in soup.find_all("a", href=True):
            add_dom_url(a.get("href"), "a[href]")
        for f in soup.find_all("form", action=True):
            add_dom_url(f.get("action"), "form[action]")
        for l in soup.find_all("link", href=True):
            add_dom_url(l.get("href"), "link[href]")
        for m in soup.find_all("meta"):
            http_equiv = (m.get("http-equiv") or "").lower()
            if http_equiv == "refresh":
                content = m.get("content") or ""
                parts = content.split("url=")
                if len(parts) > 1:
                    add_dom_url(parts[-1].strip(), "meta[refresh]")

    def extract_from_text(self, text: str, base: str, source_name: str, source_kind: str):
        # Infer method only for js/css
        if source_kind in ("js", "css"):
            self.infer_requests_from_text(text, base, source_name)

        # WS
        for m in self.WS_RE.finditer(text):
            url = m.group(1)
            ln = line_number_from_index(text, m.start())
            self.add_finding(self.results["endpoints"]["websocket"], {"url": url, "found_in": source_name, "line": ln})

        # URLs absolutas
        for m in self.ABS_URL_RE.finditer(text):
            u = m.group(0)
            ln = line_number_from_index(text, m.start())
            lower = u.lower()

            params = extract_query_params(u)

            is_apiish = any(x in lower for x in ["/api/", "/graphql", "/gql", "/v1/", "/v2/", "/v3/", "/oauth", "/auth", "/token"])
            if is_apiish:
                self.add_finding(self.results["endpoints"]["absolute"], {"url": u, "params": params, "found_in": source_name, "line": ln})
            if self.GRAPHQL_HINT_RE.search(u):
                self.add_finding(self.results["endpoints"]["graphql"], {"url_or_path": u, "found_in": source_name, "line": ln})

        # Relativas API-ish
        for m in self.REL_ENDPOINT_RE.finditer(text):
            path = m.group(1)
            ln = line_number_from_index(text, m.start())
            full = urljoin(base, path)
            self.add_finding(self.results["endpoints"]["relative"], {"path": path, "full_url": full, "found_in": source_name, "line": ln})
            if self.GRAPHQL_HINT_RE.search(path):
                self.add_finding(self.results["endpoints"]["graphql"], {"url_or_path": path, "found_in": source_name, "line": ln})

        # Base URLs
        for m in self.BASEURL_RE.finditer(text):
            val = m.group(2)
            ln = line_number_from_index(text, m.start())
            self.add_finding(self.results["endpoints"]["base_urls"], {"value": val, "found_in": source_name, "line": ln})

        # Firebase strict
        if self.FIREBASE_HINT_RE.search(text):
            for m in self.FIREBASE_STRICT_RE.finditer(text):
                blob = m.group(1).strip()
                ln = line_number_from_index(text, m.start())
                self.add_finding(self.results["exposed_configs"]["firebase"], {"blob": blob, "found_in": source_name, "line": ln})

        # AWS hints
        for m in self.COGNITO_RE.finditer(text):
            hit = m.group(1)
            ln = line_number_from_index(text, m.start())
            self.add_finding(self.results["exposed_configs"]["aws_amplify_cognito"], {"hit": hit, "found_in": source_name, "line": ln})

        for m in self.APPSYNC_RE.finditer(text):
            hit = m.group(1)
            ln = line_number_from_index(text, m.start())
            self.add_finding(self.results["exposed_configs"]["aws_appsync_amplify"], {"hit": hit, "found_in": source_name, "line": ln})

        # Sentry / GA / Segment
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

        # Rutas desde JS/CSS (con filtro fuerte)
        if source_kind in ("js", "css"):
            for m in self.ROUTE_RE.finditer(text):
                p = m.group(1)
                if not self.looks_like_real_route(p):
                    continue
                ln = line_number_from_index(text, m.start())
                full = urljoin(base, p)
                self.add_finding(self.results["inventory"]["routes_full_urls"], {"path": p, "full_url": full, "found_in": source_name, "line": ln})

    # -----------------------------
    # Sourcemaps
    # -----------------------------
    def try_fetch_sourcemap(self, asset_url: str, asset_text: str, base_origin_url: str):
        m = self.SOURCEMAP_RE.search(asset_text)
        if not m:
            return
        map_ref = m.group(1).strip().strip('"').strip("'")
        map_url = urljoin(asset_url, map_ref)
        if not same_origin(map_url, base_origin_url):
            return
        self.results["stats"]["maps_found"] += 1
        if self.results["stats"]["maps_fetched"] >= self.max_map_files:
            return

        fr = self.fetch(map_url)
        if not fr or fr.status >= 400:
            return
        try:
            data = json.loads(fr.text)
        except Exception:
            return

        self.results["stats"]["maps_fetched"] += 1
        self.results["exposed_configs"]["other"].append({
            "sourcemap": {
                "map_url": map_url,
                "file": data.get("file"),
                "sources_sample": cap_list((data.get("sources") or []), 40),
                "names_sample": cap_list((data.get("names") or []), 50),
            }
        })

        for i, sc in enumerate(cap_list((data.get("sourcesContent") or []), 10)):
            if isinstance(sc, str) and sc:
                self.extract_from_text(sc, base_origin_url, f"SOURCEMAP sourcesContent[{i}] @ {map_url}", source_kind="js")

    # -----------------------------
    # Screenshot
    # -----------------------------
    def take_screenshot(self) -> Optional[str]:
        if not self.enable_screenshot:
            return None
        try:
            from playwright.sync_api import sync_playwright  # type: ignore
        except Exception:
            self.results["notes"].append("Playwright no instalado: sin screenshot.")
            return None

        screenshot_path = os.path.join(self.out_dir, "screenshot.png")
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page(viewport={"width": 1366, "height": 768})
                page.goto(self.target_url, timeout=30000, wait_until="domcontentloaded")
                try:
                    page.wait_for_load_state("networkidle", timeout=12000)
                except Exception:
                    pass
                page.screenshot(path=screenshot_path, full_page=True)
                browser.close()
            return screenshot_path
        except Exception as e:
            self.results["notes"].append(f"Screenshot error: {e}")
            return None

    # -----------------------------
    # Main scan
    # -----------------------------
    def scan_source_and_assets(self):
        print(f"[*] Analizando HTML y assets (same-origin)...")
        fr = self.fetch(self.target_url)
        if not fr:
            print(f"{Fore.RED}[!] No pude acceder a la URL.")
            return

        self.results["final_url"] = fr.url
        base = fr.url

        self.results["server_headers"] = summarize_headers(fr.headers)
        self.fingerprint_html_and_headers(fr.text, fr.headers)

        soup = BeautifulSoup(fr.text, "html.parser")

        # Links internos (same-origin)
        internal_links: Set[str] = set()
        for a in soup.find_all("a", href=True):
            u = urljoin(base, a["href"])
            if same_origin(u, base):
                internal_links.add(u)
        self.results["inventory"]["internal_links"] = sorted(internal_links)

        # Rutas desde DOM (limpio)
        self.extract_routes_from_dom(soup, base)

        # Assets
        scripts = [urljoin(base, s["src"]) for s in soup.find_all("script", src=True)]
        styles = []
        for l in soup.find_all("link", href=True):
            rel = " ".join(l.get("rel", [])).lower()
            if "stylesheet" in rel:
                styles.append(urljoin(base, l["href"]))
        imgs = [urljoin(base, im["src"]) for im in soup.find_all("img", src=True)]

        # Next.js: __NEXT_DATA__
        next_data = soup.find("script", {"id": "__NEXT_DATA__"})
        if next_data and next_data.string:
            try:
                data = json.loads(next_data.string)
                self.results["nextjs"]["buildId"] = data.get("buildId")
                self.results["nextjs"]["page"] = data.get("page")
                self.results["nextjs"]["detected"] = True
            except Exception:
                pass

        self.results["nextjs"]["assets"]["scripts"] = uniq_list(scripts)
        self.results["nextjs"]["assets"]["styles"] = uniq_list(styles)
        self.results["nextjs"]["assets"]["images"] = uniq_list(imgs)

        self.results["inventory"]["assets"]["scripts"] = self.results["nextjs"]["assets"]["scripts"]
        self.results["inventory"]["assets"]["styles"] = self.results["nextjs"]["assets"]["styles"]
        self.results["inventory"]["assets"]["images"] = self.results["nextjs"]["assets"]["images"]

        # Extraer info del HTML (sin rutas “JS”, solo urls/endpoints/config)
        self.extract_from_text(fr.text, base, f"HTML: {base}", source_kind="html")

        # Descarga assets (same-origin, limitado)
        asset_urls = uniq_list(scripts + styles)
        fetched = 0
        for u in asset_urls:
            if fetched >= self.max_assets:
                break
            if not same_origin(u, base):
                continue

            ar = self.fetch(u)
            time.sleep(self.sleep_between)
            if not ar or ar.status >= 400:
                continue

            fetched += 1
            self.results["stats"]["assets_fetched"] = fetched

            is_js = u.lower().endswith(".js") or "javascript" in (ar.content_type or "")
            kind = "js" if is_js else "css"

            self.extract_from_text(ar.text, base, f"ASSET: {u}", source_kind=kind)

            if is_js:
                self.try_fetch_sourcemap(u, ar.text, base)

        # Screenshot
        ss = self.take_screenshot()
        if ss:
            self.results["screenshot"] = "screenshot.png"

        # Dedup
        self._dedup_findings()

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

        self.results["technologies"] = sorted(set(self.results["technologies"]))
        self.results["fingerprints"] = sorted(set(self.results["fingerprints"]))
        self.results["backend_hints"] = uniq_list(self.results["backend_hints"])

        ep = self.results["endpoints"]
        ep["absolute"] = dedup_list_of_dict(ep["absolute"], ["url", "found_in", "line"])
        ep["relative"] = dedup_list_of_dict(ep["relative"], ["full_url", "found_in", "line"])
        ep["graphql"] = dedup_list_of_dict(ep["graphql"], ["url_or_path", "found_in", "line"])
        ep["websocket"] = dedup_list_of_dict(ep["websocket"], ["url", "found_in", "line"])
        ep["base_urls"] = dedup_list_of_dict(ep["base_urls"], ["value", "found_in", "line"])
        ep["requests_inferred"] = dedup_list_of_dict(ep["requests_inferred"], ["method", "full_url", "found_in", "line"])

        inv = self.results["inventory"]
        inv["routes_full_urls"] = dedup_list_of_dict(inv["routes_full_urls"], ["full_url", "found_in", "line"])
        inv["internal_links"] = sorted(set(inv["internal_links"]))

        cfg = self.results["exposed_configs"]
        cfg["firebase"] = dedup_list_of_dict(cfg["firebase"], ["blob", "found_in", "line"])
        cfg["aws_amplify_cognito"] = dedup_list_of_dict(cfg["aws_amplify_cognito"], ["hit", "found_in", "line"])
        cfg["aws_appsync_amplify"] = dedup_list_of_dict(cfg["aws_appsync_amplify"], ["hit", "found_in", "line"])
        cfg["sentry"] = dedup_list_of_dict(cfg["sentry"], ["dsn", "found_in", "line"])
        cfg["google_analytics"] = dedup_list_of_dict(cfg["google_analytics"], ["id", "found_in", "line"])
        cfg["segment"] = dedup_list_of_dict(cfg["segment"], ["key", "found_in", "line"])

    # -----------------------------
    # HTML report helpers
    # -----------------------------
    def _card(self, title: str, body_html: str) -> str:
        return f"""
        <section class="card">
          <div class="card-h">
            <h2>{html_escape(title)}</h2>
          </div>
          <div class="card-b">{body_html}</div>
        </section>
        """

    def _badge_row(self, items: List[str]) -> str:
        if not items:
            return ""
        badges = "".join(f'<span class="badge">{html_escape(x)}</span>' for x in items)
        return f'<div class="badges">{badges}</div>'

    def _kv(self, d: Dict[str, str]) -> str:
        if not d:
            return ""
        rows = "".join(
            f"<tr><td class='k'>{html_escape(str(k))}</td><td class='v'>{html_escape(str(v))}</td></tr>"
            for k, v in d.items()
        )
        return f"<table class='kv'>{rows}</table>"

    def _table(self, cols: List[str], rows: List[List[str]]) -> str:
        if not rows:
            return ""
        head = "".join(f"<th>{html_escape(c)}</th>" for c in cols)
        body = ""
        for r in rows:
            body += "<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>"
        return f"<table class='tbl'><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"

    def _list(self, items: List[str]) -> str:
        if not items:
            return ""
        lis = "".join(f"<li>{html_escape(x)}</li>" for x in items)
        return f"<ul class='ul'>{lis}</ul>"

    def _pre(self, text: str) -> str:
        return f"<pre class='pre'>{html_escape(text)}</pre>"

    def _render_optional_cards(self) -> str:
        out = ""

        # Top: Tech + Fingerprints + Headers
        if is_truthy_list(self.results["technologies"]):
            out += self._card("Tecnologías (Wappalyzer)", self._badge_row(self.results["technologies"]))

        if is_truthy_list(self.results["fingerprints"]) or self.results["server_headers"]:
            body = ""
            if is_truthy_list(self.results["fingerprints"]):
                body += self._badge_row(self.results["fingerprints"])
            if self.results["server_headers"]:
                body += "<h3>Headers (selección)</h3>"
                body += self._kv(self.results["server_headers"])
            out += self._card("Fingerprints & Headers", body)

        if is_truthy_list(self.results["backend_hints"]):
            out += self._card("Backend hints (heurístico)", self._list(self.results["backend_hints"]))

        # Screenshot
        if self.results.get("screenshot"):
            out += self._card(
                "Screenshot",
                "<p class='muted'>Captura automática (si Playwright está instalado).</p>"
                "<img class='shot' src='screenshot.png' alt='screenshot'/>"
            )

        # Next.js
        nx = self.results["nextjs"]
        if nx.get("detected") or nx.get("buildId") or nx.get("page"):
            body = "<div class='grid2'>"
            body += f"<div><div class='pill'>Detected</div><div class='big'>{html_escape(str(nx.get('detected')))}</div></div>"
            body += f"<div><div class='pill'>buildId</div><div class='big'>{html_escape(str(nx.get('buildId')))}</div></div>"
            body += f"<div><div class='pill'>page</div><div class='big'>{html_escape(str(nx.get('page')))}</div></div>"
            body += f"<div><div class='pill'>assets</div><div class='big'>{len(nx['assets']['scripts'])} JS • {len(nx['assets']['styles'])} CSS</div></div>"
            body += "</div>"
            out += self._card("Next.js", body)

        # Inventory routes
        routes = self.results["inventory"]["routes_full_urls"]
        if is_truthy_list(routes):
            rows = []
            for r in cap_list(routes, 120):
                rows.append([
                    html_escape(str(r.get("path") or "")),
                    html_escape(str(r.get("full_url") or "")),
                    html_escape(str(r.get("found_in") or "")),
                    html_escape(str(r.get("line") if r.get("line") is not None else "")),
                ])
            out += self._card("URLs/Rutas detectadas (posibles páginas)", self._table(
                ["Path", "Full URL", "Found in", "Line"], rows
            ) + (f"<p class='muted'>Mostrando {min(len(routes), 120)} de {len(routes)}.</p>" if len(routes) > 120 else ""))

        # Internal links
        links = self.results["inventory"]["internal_links"]
        if is_truthy_list(links):
            out += self._card("Links internos (DOM)", self._list(cap_list(links, 100)) +
                              (f"<p class='muted'>Mostrando 100 de {len(links)}.</p>" if len(links) > 100 else ""))

        # Endpoints absolute/relative/graphql/ws/base_urls
        ep = self.results["endpoints"]

        if is_truthy_list(ep["base_urls"]):
            rows = []
            for x in cap_list(ep["base_urls"], 80):
                rows.append([
                    html_escape(str(x.get("value", ""))),
                    html_escape(str(x.get("found_in", ""))),
                    html_escape(str(x.get("line", ""))),
                ])
            out += self._card("Base URLs detectadas", self._table(["Value", "Found in", "Line"], rows))

        if is_truthy_list(ep["requests_inferred"]):
            rows = []
            for x in cap_list(ep["requests_inferred"], 140):
                rows.append([
                    html_escape(str(x.get("method", ""))),
                    html_escape(str(x.get("full_url", ""))),
                    html_escape(", ".join(x.get("params", []) or [])),
                    html_escape(str(x.get("evidence", ""))),
                    html_escape(str(x.get("found_in", ""))),
                    html_escape(str(x.get("line", ""))),
                ])
            out += self._card("Requests inferidos (método + endpoint)", self._table(
                ["Method", "Full URL", "Params", "Evidence", "Found in", "Line"], rows
            ) + (f"<p class='muted'>Mostrando {min(len(ep['requests_inferred']), 140)} de {len(ep['requests_inferred'])}.</p>" if len(ep["requests_inferred"]) > 140 else ""))

        if is_truthy_list(ep["absolute"]):
            rows = []
            for x in cap_list(ep["absolute"], 120):
                rows.append([
                    html_escape(str(x.get("url", ""))),
                    html_escape(", ".join(x.get("params", []) or [])),
                    html_escape(str(x.get("found_in", ""))),
                    html_escape(str(x.get("line", ""))),
                ])
            out += self._card("Endpoints absolutos (API-ish)", self._table(
                ["URL", "Params", "Found in", "Line"], rows
            ))

        if is_truthy_list(ep["relative"]):
            rows = []
            for x in cap_list(ep["relative"], 120):
                rows.append([
                    html_escape(str(x.get("path", ""))),
                    html_escape(str(x.get("full_url", ""))),
                    html_escape(str(x.get("found_in", ""))),
                    html_escape(str(x.get("line", ""))),
                ])
            out += self._card("Endpoints relativos (API-ish)", self._table(
                ["Path", "Full URL", "Found in", "Line"], rows
            ))

        if is_truthy_list(ep["graphql"]):
            rows = []
            for x in cap_list(ep["graphql"], 80):
                rows.append([
                    html_escape(str(x.get("url_or_path", ""))),
                    html_escape(str(x.get("found_in", ""))),
                    html_escape(str(x.get("line", ""))),
                ])
            out += self._card("GraphQL hints", self._table(["URL/Path", "Found in", "Line"], rows))

        if is_truthy_list(ep["websocket"]):
            rows = []
            for x in cap_list(ep["websocket"], 80):
                rows.append([
                    html_escape(str(x.get("url", ""))),
                    html_escape(str(x.get("found_in", ""))),
                    html_escape(str(x.get("line", ""))),
                ])
            out += self._card("WebSocket", self._table(["URL", "Found in", "Line"], rows))

        # Configs expuestas
        cfg = self.results["exposed_configs"]
        any_cfg = any(is_truthy_list(cfg[k]) for k in cfg.keys())
        if any_cfg:
            body = ""
            if is_truthy_list(cfg["firebase"]):
                rows = []
                for x in cap_list(cfg["firebase"], 30):
                    rows.append([html_escape(str(x.get("blob",""))), html_escape(str(x.get("found_in",""))), html_escape(str(x.get("line","")))])
                body += "<h3>Firebase</h3>" + self._table(["Blob", "Found in", "Line"], rows)

            if is_truthy_list(cfg["aws_amplify_cognito"]):
                rows = []
                for x in cap_list(cfg["aws_amplify_cognito"], 80):
                    rows.append([html_escape(str(x.get("hit",""))), html_escape(str(x.get("found_in",""))), html_escape(str(x.get("line","")))])
                body += "<h3>AWS Amplify/Cognito hints</h3>" + self._table(["Hit", "Found in", "Line"], rows)

            if is_truthy_list(cfg["aws_appsync_amplify"]):
                rows = []
                for x in cap_list(cfg["aws_appsync_amplify"], 80):
                    rows.append([html_escape(str(x.get("hit",""))), html_escape(str(x.get("found_in",""))), html_escape(str(x.get("line","")))])
                body += "<h3>AWS AppSync hints</h3>" + self._table(["Hit", "Found in", "Line"], rows)

            if is_truthy_list(cfg["sentry"]):
                rows = []
                for x in cap_list(cfg["sentry"], 30):
                    rows.append([html_escape(str(x.get("dsn",""))), html_escape(str(x.get("found_in",""))), html_escape(str(x.get("line","")))])
                body += "<h3>Sentry</h3>" + self._table(["DSN", "Found in", "Line"], rows)

            if is_truthy_list(cfg["google_analytics"]):
                rows = []
                for x in cap_list(cfg["google_analytics"], 50):
                    rows.append([html_escape(str(x.get("id",""))), html_escape(str(x.get("found_in",""))), html_escape(str(x.get("line","")))])
                body += "<h3>Google Analytics</h3>" + self._table(["ID", "Found in", "Line"], rows)

            if is_truthy_list(cfg["segment"]):
                rows = []
                for x in cap_list(cfg["segment"], 30):
                    rows.append([html_escape(str(x.get("key",""))), html_escape(str(x.get("found_in",""))), html_escape(str(x.get("line","")))])
                body += "<h3>Segment</h3>" + self._table(["Key", "Found in", "Line"], rows)

            if is_truthy_list(cfg["other"]):
                body += "<h3>Other</h3>" + self._pre(json.dumps(cfg["other"], ensure_ascii=False, indent=2)[:5000])

            out += self._card("Configs / Identificadores públicos", body)

        # Notes
        if is_truthy_list(self.results["notes"]):
            out += self._card("Notas", self._list(cap_list(self.results["notes"], 60)))

        return out

    def generate_report(self):
        out_json = os.path.join(self.out_dir, "results.json")
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(self.results, f, ensure_ascii=False, indent=2)

        # Stats
        stats = self.results["stats"]
        stats_html = f"""
        <div class="stats">
          <div class="stat"><div class="pill">Assets fetched</div><div class="big">{stats["assets_fetched"]} / {self.max_assets}</div></div>
          <div class="stat"><div class="pill">Maps found</div><div class="big">{stats["maps_found"]}</div></div>
          <div class="stat"><div class="pill">Maps fetched</div><div class="big">{stats["maps_fetched"]} / {self.max_map_files}</div></div>
        </div>
        """

        meta = self.results["meta"]
        header = f"""
        <div class="top">
          <div>
            <h1>Darkmoon • Public Exposure Report</h1>
            <p class="muted">{html_escape(meta.get("purpose",""))}</p>
            <p class="muted"><b>Disclaimer:</b> {html_escape(meta.get("disclaimer",""))}</p>
          </div>
          <div class="box">
            <div class="pill">Target</div>
            <div class="big">{html_escape(self.results.get("url",""))}</div>
            <div class="pill" style="margin-top:10px;">Final URL</div>
            <div class="big">{html_escape(self.results.get("final_url",""))}</div>
            <div class="pill" style="margin-top:10px;">Timestamp</div>
            <div class="big">{int(meta.get("timestamp", 0))}</div>
          </div>
        </div>
        """

        cards = self._render_optional_cards()

        html_content = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Darkmoon Report • {html_escape(self.results.get("final_url") or self.target_url)}</title>
  <style>
    :root {{
      --bg:#0b0f14; --panel:#0f1620; --card:#101a26; --border:#1b2a3a;
      --txt:#e6f1ff; --muted:#98a7b8; --accent:#7cffb0; --accent2:#bc13fe;
      --warn:#ffcc00;
    }}
    *{{box-sizing:border-box}}
    body{{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;background:radial-gradient(1200px 800px at 30% 10%, #132133 0%, var(--bg) 60%); color:var(--txt)}}
    a{{color:var(--accent)}}
    .wrap{{max-width:1180px;margin:auto;padding:22px}}
    .top{{display:flex;gap:16px;flex-wrap:wrap;align-items:stretch}}
    h1{{margin:0;font-size:22px;color:var(--accent2)}}
    h2{{margin:0;font-size:16px}}
    h3{{margin:14px 0 8px;color:var(--accent)}}
    .muted{{color:var(--muted);margin:6px 0}}
    .box{{flex:1;min-width:320px;background:linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01));border:1px solid var(--border);border-radius:14px;padding:14px}}
    .stats{{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}}
    .stat{{flex:1;min-width:220px;background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:12px}}
    .pill{{display:inline-block;padding:4px 10px;border-radius:999px;border:1px solid var(--border);background:rgba(255,255,255,0.03);color:var(--muted);font-size:12px}}
    .big{{margin-top:6px;font-size:14px;word-break:break-all}}
    .grid{{display:grid;grid-template-columns:1fr;gap:14px}}
    @media (min-width: 920px) {{
      .grid{{grid-template-columns:1fr 1fr}}
    }}
    .card{{background:var(--card);border:1px solid var(--border);border-radius:16px;overflow:hidden}}
    .card-h{{padding:12px 14px;border-bottom:1px solid var(--border);background:rgba(255,255,255,0.02)}}
    .card-b{{padding:12px 14px}}
    .badges{{display:flex;flex-wrap:wrap;gap:8px}}
    .badge{{padding:6px 10px;border-radius:999px;background:rgba(124,255,176,0.08);border:1px solid rgba(124,255,176,0.25);color:var(--accent);font-size:12px}}
    .ul{{margin:0;padding-left:18px}}
    .ul li{{margin:6px 0;color:var(--txt)}}
    .kv{{width:100%;border-collapse:collapse;font-size:12px}}
    .kv td{{border-bottom:1px solid rgba(255,255,255,0.06);padding:8px 8px;vertical-align:top}}
    .kv td.k{{color:var(--muted);width:220px}}
    .tbl{{width:100%;border-collapse:collapse;font-size:12px;table-layout:fixed}}
    .tbl th,.tbl td{{border-bottom:1px solid rgba(255,255,255,0.07);padding:8px 8px;vertical-align:top}}
    .tbl th{{text-align:left;color:var(--muted);font-weight:600;background:rgba(255,255,255,0.02)}}
    .tbl td{{word-break:break-word}}
    .pre{{background:#08101a;border:1px solid var(--border);padding:10px;border-radius:12px;overflow:auto;color:#ffeb3b;max-height:420px}}
    .shot{{width:100%;border-radius:12px;border:1px solid var(--border);margin-top:10px}}
    .grid2{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
    footer{{text-align:center;color:var(--muted);margin:16px 0 6px;font-size:12px}}
  </style>
</head>
<body>
  <div class="wrap">
    {header}
    {stats_html}
    <div class="grid">
      {cards}
    </div>

    <section class="card" style="margin-top:14px;">
      <div class="card-h"><h2>Archivos generados</h2></div>
      <div class="card-b">
        <p class="muted">Este reporte es pasivo. Revisa el JSON para detalle completo.</p>
        <div class="badges">
          <span class="badge">results.json</span>
          <span class="badge">index.html</span>
          {"<span class='badge'>screenshot.png</span>" if self.results.get("screenshot") else ""}
        </div>
        <p class="muted" style="margin-top:10px;">Ruta: <code>{html_escape(self.out_dir)}</code></p>
      </div>
    </section>

    <footer>Darkmoon • Security Reporting</footer>
  </div>
</body>
</html>
"""

        out_html = os.path.join(self.out_dir, "index.html")
        with open(out_html, "w", encoding="utf-8") as f:
            f.write(html_content)

        print(f"\n{Fore.GREEN}[+] Reporte generado: {out_html}")
        print(f"{Fore.GREEN}[+] JSON generado: {out_json}")

    # -----------------------------
    # Run
    # -----------------------------
    def run(self):
        self.print_banner()
        self.identify_tech_wappalyzer()
        self.scan_source_and_assets()
        self.generate_report()
        print(f"\n{Fore.MAGENTA}Darkmoon • Security Reporting")


def main():
    p = argparse.ArgumentParser(description="DarkmLens v3.2 (Darkmoon) - Passive exposure report")
    p.add_argument("url", help="Target URL (https://example.com/path)")
    p.add_argument("--out", default="out", help="Output folder")
    p.add_argument("--max-assets", type=int, default=120, help="Max same-origin assets to fetch")
    p.add_argument("--max-maps", type=int, default=20, help="Max sourcemaps to fetch")
    p.add_argument("--timeout", type=int, default=15, help="Request timeout seconds")
    p.add_argument("--sleep", type=float, default=0.03, help="Sleep between asset fetches")
    p.add_argument("--no-screenshot", action="store_true", help="Disable screenshot (Playwright)")
    args = p.parse_args()

    target = args.url.strip()
    if not target.startswith("http"):
        target = "https://" + target

    s = DarkmLens(
        target_url=target,
        out_dir=args.out,
        max_assets=args.max_assets,
        max_map_files=args.max_maps,
        request_timeout=args.timeout,
        sleep_between=args.sleep,
        screenshot=not args.no_screenshot,
    )
    s.run()


if __name__ == "__main__":
    main()
