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
from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
import urllib3
from bs4 import BeautifulSoup
from colorama import Fore, init
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
# Scanner
# =============================
class DarkmLens:
    """
    DarkmLens v4.3 (Darkmoon)
    - Defensive passive analysis (authorized only).
    - NEW in v4.3:
      * Threading / parallel fetch:
        - assets (JS/CSS)
        - crawl (same-origin) using a work queue
        - authz audit routes
        - deep-endpoints scripts per visited HTML
      * Thread-local requests session to avoid sharing Session across threads
      * Extra CLI: --threads / --asset-threads / --crawl-threads / --authz-threads / --deep-threads
    """

    VERSION = "4.3"

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
    FIREBASE_STRICT_RE = re.compile(
        r'({[^{}]{0,1200}'
        r'(apiKey\s*[:=]\s*["\'][^"\']+["\'])'
        r'[^{}]{0,1200}'
        r'(authDomain\s*[:=]\s*["\'][^"\']+["\'])'
        r'[^{}]{0,1200}'
        r'(projectId\s*[:=]\s*["\'][^"\']+["\'])'
        r'[^{}]{0,1200}'
        r'(storageBucket|messagingSenderId|appId)'
        r'[^{}]{0,1200}})',
        re.IGNORECASE
    )
    FIRESTORE_REST_RE = re.compile(r'https:\/\/firestore\.googleapis\.com\/v1\/projects\/[^"\']+?\/databases\/\([^"\']+?\)\/documents\/[^"\']+', re.IGNORECASE)
    FIRESTORE_DOCS_PATH_RE = re.compile(r'\/documents\/([^?\s"\'<>#]+)', re.IGNORECASE)
    RTDB_RE = re.compile(r'https:\/\/([a-z0-9-]+)\.firebaseio\.com\/([^"\']+?)\.json', re.IGNORECASE)
    FIRESTORE_COLLECTION_CALL_RE = re.compile(r'\bcollection\s*\(\s*["\']([a-zA-Z0-9_-]{1,80})["\']\s*\)', re.IGNORECASE)
    FIRESTORE_COLLECTIONGROUP_CALL_RE = re.compile(r'\bcollectionGroup\s*\(\s*["\']([a-zA-Z0-9_-]{1,80})["\']\s*\)', re.IGNORECASE)

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

        # Optional AI summary (Ollama)
        ai_ollama: bool = False,
        ai_model: str = "llama3.1:8b",

        # NEW
        deep_endpoints: bool = False,

        # THREADS
        threads: int = 12,
        asset_threads: Optional[int] = None,
        crawl_threads: Optional[int] = None,
        authz_threads: Optional[int] = None,
        deep_threads: Optional[int] = None,
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
        self.ai_model = ai_model

        self.deep_endpoints = deep_endpoints
        self.verbose = False  # set via CLI

        # Thread controls
        self.threads = max(1, int(threads))
        self.asset_threads = max(1, int(asset_threads if asset_threads is not None else self.threads))
        self.crawl_threads = max(1, int(crawl_threads if crawl_threads is not None else min(self.threads, 10)))
        self.authz_threads = max(1, int(authz_threads if authz_threads is not None else min(self.threads, 20)))
        self.deep_threads = max(1, int(deep_threads if deep_threads is not None else min(self.threads, 10)))

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
            },
            "firebase": {
                "detected": False,
                "configs": [],
                "firestore_rest": [],
                "rtdb": [],
                "collections_probable": [],
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
            "stats": {
                "assets_fetched": 0,
                "maps_found": 0,
                "maps_fetched": 0,
                "pages_visited": 0,
                "authz_routes_tested": 0
            }
        }

    # -----------------------------
    # Template
    # -----------------------------
    def _ensure_template(self):
        if os.path.exists(self.template_path):
            return
        write_text_file(self.template_path, DEFAULT_REPORT_TEMPLATE)

    # -----------------------------
    # UI
    # -----------------------------
    def print_banner(self):
        print(f"{Fore.CYAN}========================================")
        print(f"{Fore.MAGENTA}   DarkmLens v{self.VERSION}  |  Darkmoon | Red Team Barranquilla")
        print(f"{Fore.CYAN}========================================")
        print(f"{Fore.YELLOW}Uso autorizado únicamente. Análisis pasivo.\n")
        print(f"{Fore.CYAN}Threads: global={self.threads} assets={self.asset_threads} crawl={self.crawl_threads} authz={self.authz_threads} deep={self.deep_threads}\n")

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
                "body_keys": [],
                "body_hint": None,
                "headers_hint": None,
                "found_in": source_name,
                "line": ln,
                "evidence": f"axios.{meth.lower()}(...)",
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

    def extract_from_text(self, text: str, base: str, source_name: str, source_kind: str):
        if not text:
            return

        if source_kind in ("js", "css", "html"):
            self.infer_requests_from_text(text, base, source_name)

        if source_kind in ("js", "html"):
            self._extract_js_navigation_routes(text, base, source_name, source_kind)

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

        if self.FIREBASE_HINT_RE.search(text):
            with self._results_lock:
                self.results["firebase"]["detected"] = True
            for m in self.FIREBASE_STRICT_RE.finditer(text):
                blob = m.group(1).strip()
                ln = line_number_from_index(text, m.start())
                self.add_finding(self.results["firebase"]["configs"], {"blob": blob, "found_in": source_name, "line": ln})

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
                    try:
                        soup = BeautifulSoup(fr.text, "html.parser")
                    except Exception:
                        soup = None

                    if soup is not None:
                        self.extract_routes_from_dom(soup, base, page_url=url)

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

    # -----------------------------
    # Main scan (root + assets) [assets threaded]
    # -----------------------------
    def scan_source_and_assets(self):
        print(f"[*] Analizando HTML inicial y assets (same-origin)...")
        fr = self.fetch(self.target_url)
        if not fr:
            print(f"{Fore.RED}[!] No pude acceder a la URL.")
            return

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
            subprocess.run(["ollama", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
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
            cp = subprocess.run(
                ["ollama", "run", self.ai_model],
                input=prompt.encode("utf-8", errors="ignore"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=12,
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
            ep["requests_inferred"] = dedup_list_of_dict(ep["requests_inferred"], ["method", "full_url", "found_in", "line"])

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
    # Run
    # -----------------------------
    def run(self):
        self.print_banner()
        self.identify_tech_wappalyzer()
        self.scan_source_and_assets()
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


def main():
    p = argparse.ArgumentParser(description="DarkmLens v4.3 (Darkmoon) - Passive exposure report (authorized only)")
    p.add_argument("url", help="Target URL (https://example.com/path)")
    p.add_argument("--out", default="out", help="Output folder")
    p.add_argument("--max-assets", type=int, default=120, help="Max same-origin assets to fetch")
    p.add_argument("--max-maps", type=int, default=20, help="Max sourcemaps to fetch")
    p.add_argument("--timeout", type=int, default=15, help="Request timeout seconds")
    p.add_argument("--sleep", type=float, default=0.03, help="Sleep between fetches (per request). Set 0 for max speed (risky).")
    p.add_argument("--no-screenshot", action="store_true", help="Disable screenshots (Playwright)")

    p.add_argument("--no-crawl", action="store_true", help="Disable same-origin crawling of pages")
    p.add_argument("--max-pages", type=int, default=25, help="Max pages to visit (crawl)")
    p.add_argument("--max-depth", type=int, default=2, help="Max crawl depth")

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

    # Optional local AI (Ollama)
    p.add_argument("--ai-ollama", action="store_true", help="Use local Ollama to summarize each route (optional)")
    p.add_argument("--ai-model", default="llama3.1:8b", help="Ollama model name (example: llama3.1:8b)")

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

    args = p.parse_args()

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
        ai_model=args.ai_model,

        deep_endpoints=args.deep_endpoints,

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
# (Tu template original se mantiene tal cual)
# =============================
DEFAULT_REPORT_TEMPLATE = r"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Darkmoon Report</title>
  <style>
   .full { width: 100%; grid-column: 1 / -1; }
    :root{
      --bg:#0b0f14; --panel:#0f1620; --card:#101a26; --border:#1b2a3a;
      --txt:#e6f1ff; --muted:#98a7b8; --accent:#7cffb0; --accent2:#bc13fe;
      --red:#ff5b5b; --orange:#ffb020; --blue:#57a3ff;
    }
    *{box-sizing:border-box}
    body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;background:radial-gradient(1200px 800px at 30% 10%, #132133 0%, var(--bg) 60%); color:var(--txt)}
    a{color:var(--accent);text-decoration:none}
    a:hover{text-decoration:underline}
    code{background:rgba(255,255,255,0.05);padding:2px 6px;border-radius:8px;border:1px solid rgba(255,255,255,0.08)}
    .wrap{max-width:1280px;margin:auto;padding:22px}
    .top{display:flex;gap:16px;flex-wrap:wrap;align-items:stretch}
    h1{margin:0;font-size:22px;color:var(--accent2)}
    h2{margin:0;font-size:16px}
    h3{margin:14px 0 8px;color:var(--accent)}
    .muted{color:var(--muted);margin:6px 0}
    .box{flex:1;min-width:320px;background:linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01));border:1px solid var(--border);border-radius:14px;padding:14px}
    .stats{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}
    .stat{flex:1;min-width:220px;background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:12px}
    .pill{display:inline-block;padding:4px 10px;border-radius:999px;border:1px solid var(--border);background:rgba(255,255,255,0.03);color:var(--muted);font-size:12px}
    .big{margin-top:6px;font-size:14px;word-break:break-all}
    .grid{display:grid;grid-template-columns:1fr;gap:14px}
    @media (min-width: 920px) {.grid{grid-template-columns:1fr 1fr}}
    .card{background:var(--card);border:1px solid var(--border);border-radius:16px;overflow:hidden}
    .card-h{padding:12px 14px;border-bottom:1px solid var(--border);background:rgba(255,255,255,0.02);display:flex;justify-content:space-between;align-items:center;gap:10px}
    .card-b{padding:12px 14px}
    .badges{display:flex;flex-wrap:wrap;gap:8px}
    .badge{padding:6px 10px;border-radius:999px;background:rgba(124,255,176,0.08);border:1px solid rgba(124,255,176,0.25);color:var(--accent);font-size:12px}
    .badge.red{background:rgba(255,91,91,0.10);border-color:rgba(255,91,91,0.30);color:var(--red)}
    .badge.orange{background:rgba(255,176,32,0.10);border-color:rgba(255,176,32,0.30);color:var(--orange)}
    .badge.blue{background:rgba(87,163,255,0.10);border-color:rgba(87,163,255,0.30);color:var(--blue)}
    .badge.gray{background:rgba(255,255,255,0.06);border-color:rgba(255,255,255,0.12);color:var(--muted)}
    .kv{width:100%;border-collapse:collapse;font-size:12px}
    .kv td{border-bottom:1px solid rgba(255,255,255,0.06);padding:8px 8px;vertical-align:top}
    .kv td.k{color:var(--muted);width:240px}
    .tbl{width:100%;border-collapse:collapse;font-size:12px;table-layout:fixed}
    .tbl th,.tbl td{border-bottom:1px solid rgba(255,255,255,0.07);padding:8px 8px;vertical-align:top}
    .tbl th{text-align:left;color:var(--muted);font-weight:600;background:rgba(255,255,255,0.02)}
    .tbl td{word-break:break-word}
    .pre{background:#08101a;border:1px solid var(--border);padding:10px;border-radius:12px;overflow:auto;color:#ffeb3b;max-height:420px}
    .shot{width:100%;border-radius:12px;border:1px solid var(--border);margin-top:10px}
    .controls{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    .search{flex:1;min-width:260px;background:rgba(255,255,255,0.03);border:1px solid var(--border);color:var(--txt);padding:10px 12px;border-radius:12px;outline:none}
    .search::placeholder{color:rgba(152,167,184,0.75)}
    .fbtn{cursor:pointer;border:1px solid var(--border);background:rgba(255,255,255,0.02);color:var(--muted);padding:8px 10px;border-radius:999px;font-size:12px}
    .fbtn.active{border-color:rgba(124,255,176,0.35);color:var(--accent);background:rgba(124,255,176,0.08)}
    footer{text-align:center;color:var(--muted);margin:16px 0 6px;font-size:12px}

    /* Gallery */
    .gal-grid{display:grid;grid-template-columns:repeat(1,minmax(0,1fr));gap:12px}
    @media (min-width: 720px){.gal-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
    @media (min-width: 1080px){.gal-grid{grid-template-columns:repeat(3,minmax(0,1fr))}}
    @media (min-width: 1400px){.gal-grid{grid-template-columns:repeat(4,minmax(0,1fr))}}
    .tile{display:block;text-decoration:none;border:1px solid var(--border);border-radius:14px;overflow:hidden;background:rgba(255,255,255,0.02);transition:transform .12s ease, border-color .12s ease}
    .tile:hover{transform:translateY(-1px);border-color:rgba(124,255,176,0.28)}
    .tile-top{display:flex;gap:8px;justify-content:space-between;align-items:center;padding:10px 10px 0}
    .chip{display:inline-block;padding:4px 9px;border-radius:999px;border:1px solid rgba(255,255,255,0.10);background:rgba(0,0,0,0.18);color:var(--txt);font-size:12px}
    .thumb{width:100%;height:190px;object-fit:cover;border-top:1px solid rgba(255,255,255,0.06);border-bottom:1px solid rgba(255,255,255,0.06)}
    .tile-bot{padding:10px}
    .t-url{font-size:12px;color:var(--txt);word-break:break-all}
    .t-meta{margin-top:6px;font-size:11px;color:var(--muted);word-break:break-word}
    .t-mini{margin-top:6px;font-size:11px;color:rgba(152,167,184,0.85);word-break:break-word}

    /* Collapsible cards */
    details > summary { list-style: none; cursor: pointer; }
    details > summary::-webkit-details-marker { display:none; }
  </style>
</head>
<body>
  <div class="wrap" id="app"></div>

<script>
const RESULTS = __RESULTS_JSON__;

function esc(s){ return String(s ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'","&#39;"); }
function badge(text, cls=''){ return `<span class="badge ${cls}">${esc(text)}</span>`; }
function pill(text){ return `<span class="pill">${esc(text)}</span>`; }

function kvTable(obj){
  if(!obj || Object.keys(obj).length===0) return '';
  const rows = Object.entries(obj).map(([k,v])=>`<tr><td class="k">${esc(k)}</td><td class="v">${esc(v)}</td></tr>`).join('');
  return `<table class="kv">${rows}</table>`;
}

function table(cols, rows){
  if(!rows || rows.length===0) return '';
  const head = cols.map(c=>`<th>${esc(c)}</th>`).join('');
  const body = rows.map(r=>`<tr>${r.map(c=>`<td>${c}</td>`).join('')}</tr>`).join('');
  return `<table class="tbl"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

function card(title, body, extraClass=""){
  const cls = extraClass ? `card ${extraClass}` : "card";
  return `<details class="${cls}" open>
    <summary class="card-h"><h2>${esc(title)}</h2><div class="pill">toggle</div></summary>
    <div class="card-b">${body}</div>
  </details>`;
}

function accessBadge(state){
  if(state === 'con acceso') return badge('con acceso', 'blue');
  if(state === 'sin acceso') return badge('sin acceso', 'red');
  return badge(state || '—', 'gray');
}

function statusBadge(code){
  if(code == null) return badge('—','gray');
  const n = Number(code);
  if(n >= 200 && n < 300) return badge(String(n),'blue');
  if(n === 401) return badge('401','orange');
  if(n === 403) return badge('403','orange');
  if(n >= 300 && n < 400) return badge(String(n),'gray');
  if(n >= 400) return badge(String(n),'red');
  return badge(String(n),'gray');
}

function wireTableSearch(inputId, wrapId, countId){
  const input = document.getElementById(inputId);
  const wrap = document.getElementById(wrapId);
  const count = document.getElementById(countId);
  if(!input || !wrap) return;

  function apply(){
    const q = (input.value || '').toLowerCase().trim();
    const rows = wrap.querySelectorAll('tbody tr');
    let shown = 0;
    rows.forEach(tr=>{
      const text = tr.innerText.toLowerCase();
      const ok = !q || text.includes(q);
      tr.style.display = ok ? '' : 'none';
      if(ok) shown++;
    });
    if(count) count.textContent = String(shown);
  }

  input.addEventListener('input', apply);
  apply();
}

function build(){
  const meta = RESULTS.meta || {};
  const stats = RESULTS.stats || {};
  const app = document.getElementById('app');

  const header = `
    <div class="top">
      <div style="flex:1;min-width:320px">
        <h1>Darkmoon • Public Exposure Report</h1>
        <p class="muted">${esc(meta.purpose||'')}</p>
        <p class="muted"><b>Disclaimer:</b> ${esc(meta.disclaimer||'')}</p>
        <div class="badges" style="margin-top:10px;">
          ${(RESULTS.framework_hints||[]).map(x=>badge(x,'gray')).join('')}
          ${(RESULTS.fingerprints||[]).slice(0,8).map(x=>badge(x,'gray')).join('')}
        </div>
      </div>
      <div class="box">
        ${pill('Target')}<div class="big">${esc(RESULTS.url||'')}</div>
        <div style="height:10px"></div>
        ${pill('Final URL')}<div class="big">${esc(RESULTS.final_url||'')}</div>
        <div style="height:10px"></div>
        ${pill('Timestamp')}<div class="big">${esc(meta.timestamp||'')}</div>
        <div style="height:10px"></div>
        ${pill('Auth headers')}<div class="big">${esc((RESULTS.server_headers && Object.keys(RESULTS.server_headers).length>0) ? 'YES' : '—')}</div>
      </div>
    </div>`;

  const statsHtml = `
    <div class="stats">
      <div class="stat">${pill('Assets fetched')}<div class="big">${esc(stats.assets_fetched||0)}</div></div>
      <div class="stat">${pill('Maps found')}<div class="big">${esc(stats.maps_found||0)}</div></div>
      <div class="stat">${pill('Maps fetched')}<div class="big">${esc(stats.maps_fetched||0)}</div></div>
      <div class="stat">${pill('Pages visited')}<div class="big">${esc(stats.pages_visited||0)} / ${esc((RESULTS?.crawl?.max_pages||0))}</div></div>
      <div class="stat">${pill('AuthZ routes tested')}<div class="big">${esc(stats.authz_routes_tested||0)} / ${esc(RESULTS?.authz_audit?.max_routes||0)}</div></div>
    </div>`;

  let cards = '';

  if((RESULTS.technologies||[]).length){
    cards += card('Tecnologías (Wappalyzer)',
      `<div class="badges">${RESULTS.technologies.map(x=>badge(x)).join('')}</div>`,'full'
    );
  }

  if((RESULTS.fingerprints||[]).length || (RESULTS.server_headers && Object.keys(RESULTS.server_headers).length)){
    cards += card('Fingerprints & Headers',
      `<div class="badges">${(RESULTS.fingerprints||[]).map(x=>badge(x,'gray')).join('')}</div>
       <h3>Headers (selección)</h3>${kvTable(RESULTS.server_headers||{})}`,'full'
    );
  }

  if((RESULTS.backend_hints||[]).length){
    cards += card('Backend hints (heurístico)',
      `<ul>${RESULTS.backend_hints.map(x=>`<li>${esc(x)}</li>`).join('')}</ul>`,'full'
    );
  }

  // Screenshot principal (full row)
  if(RESULTS.screenshots && RESULTS.screenshots.main){
    cards += `<details class="card full" open>
      <summary class="card-h"><h2>Screenshot (principal)</h2><div class="pill">toggle</div></summary>
      <div class="card-b">
        <p class="muted">Captura automática (si Playwright está instalado).</p>
        <img class="shot" src="${esc(RESULTS.screenshots.main)}" alt="screenshot"/>
      </div>
    </details>`;
  }

  // NEW: Backend endpoints summary (compact)
  const inferred = (RESULTS.endpoints && RESULTS.endpoints.requests_inferred) ? RESULTS.endpoints.requests_inferred : [];
  const abs = (RESULTS.endpoints && RESULTS.endpoints.absolute) ? RESULTS.endpoints.absolute : [];
  const rel = (RESULTS.endpoints && RESULTS.endpoints.relative) ? RESULTS.endpoints.relative : [];
  const gql = (RESULTS.endpoints && RESULTS.endpoints.graphql) ? RESULTS.endpoints.graphql : [];
  const ws = (RESULTS.endpoints && RESULTS.endpoints.websocket) ? RESULTS.endpoints.websocket : [];
  const bases = (RESULTS.endpoints && RESULTS.endpoints.base_urls) ? RESULTS.endpoints.base_urls : [];

  const backendRows = [];
  inferred.slice(0,220).forEach(x=>{
    backendRows.push([
      `<div class="badges">${badge((x.method||'UNKNOWN').toUpperCase(),'blue')}</div>`,
      `<a href="${esc(x.full_url||'')}" target="_blank">${esc(x.full_url||'')}</a>`,
      `<div class="badges">${(x.params||[]).length ? (x.params||[]).map(p=>badge(p,'gray')).join('') : badge('—','gray')}</div>`,
      `<div class="badges">${(x.body_keys||[]).length ? (x.body_keys||[]).map(p=>badge(p,'gray')).join('') : badge('—','gray')}</div>`,
      `<div class="t-mini">${esc(x.evidence||'')}</div>`,
      `<div class="t-mini">${esc(x.found_in||'')} : ${esc(x.line||'')}</div>`
    ]);
  });

  if(backendRows.length || abs.length || rel.length || gql.length || ws.length || bases.length){
    const extraBadges = `
      <div class="badges">
        ${badge(`requests_inferred: ${inferred.length}`,'gray')}
        ${badge(`absolute: ${abs.length}`,'gray')}
        ${badge(`relative: ${rel.length}`,'gray')}
        ${badge(`graphql: ${gql.length}`,'gray')}
        ${badge(`websocket: ${ws.length}`,'gray')}
        ${badge(`base_urls: ${bases.length}`,'gray')}
      </div>
    `;

    cards += card('Backend endpoints encontrados (resumen)',
      `
      ${extraBadges}
      <div class="controls" style="margin-top:10px">
        <input id="beSearch" class="search" placeholder="Buscar en endpoints (método/url/params/body)...">
      </div>
      <p class="muted">Mostrando <span id="beCount">${Math.min(backendRows.length,220)}</span> de ${backendRows.length} inferidos (fetch/axios/etc).</p>
      <div id="beTable">${table(['Method','Full URL','Query params','Body keys','Evidence','Found in'], backendRows)}</div>
      `,'full'
    );
  }

  // AuthZ audit table
  const authItems = (RESULTS.authz_audit && RESULTS.authz_audit.items) ? RESULTS.authz_audit.items : [];
  if(authItems.length){
    const controls = `
      <div class="controls">
        <input id="authSearch" class="search" placeholder="Buscar por URL / ruta...">
        <button class="fbtn active" data-filter="all">Todas</button>
        <button class="fbtn" data-filter="access">Con acceso</button>
        <button class="fbtn" data-filter="noaccess">Sin acceso</button>
        <button class="fbtn" data-filter="401">401</button>
        <button class="fbtn" data-filter="403">403</button>
        <button class="fbtn" data-filter="404">404</button>
      </div>
      <p class="muted" style="margin-top:8px">Mostrando <span id="authCount">${authItems.length}</span> rutas.</p>
    `;

    const rows = authItems.map(it => {
      const url = it.url || '';
      const shot = it.screenshot ? `<a href="${esc(it.screenshot)}" target="_blank">ver</a>` : '';
      const params = (it.params||[]).length ? (it.params||[]).map(x=>badge(x,'gray')).join('') : badge('—','gray');
      const bkeys = (it.body_keys||[]).length ? (it.body_keys||[]).map(x=>badge(x,'gray')).join('') : badge('—','gray');
      const methods = (it.methods||[]).length ? (it.methods||[]).map(x=>badge(x,'blue')).join('') : badge('GET','blue');
      const ai = it.ai_summary ? `<div class="t-mini">${esc(it.ai_summary)}</div>` : '';

      return [
        `<div>${statusBadge(it.status)} ${accessBadge(it.state)}</div>
         <div class="t-mini">${esc(it.reason||'')}</div>`,
        `<div><a href="${esc(url)}" target="_blank">${esc(url)}</a></div>${ai}`,
        `<div class="badges">${methods}</div>`,
        `<div class="badges">${params}</div>`,
        `<div class="badges">${bkeys}</div>`,
        `${shot}`,
        `${it.saved_body ? `<code>${esc(it.saved_body)}</code>` : ''}`
      ];
    });

    cards += card('AuthZ Audit (estado por ruta)',
      `${controls}
       <div id="authTable">${table(
        ['Estado', 'URL', 'Métodos', 'Query params', 'Body keys', 'Screenshot', 'Saved body'],
        rows
       )}</div>`,'full'
    );
  }

  // Routes discovered (with search)
  const routes = (RESULTS.inventory && RESULTS.inventory.routes_full_urls) ? RESULTS.inventory.routes_full_urls : [];
  if(routes.length){
    const rows = routes.slice(0,180).map(r => [
      `<code>${esc(r.path||'')}</code>`,
      `<a href="${esc(r.full_url||'')}" target="_blank">${esc(r.full_url||'')}</a>`,
      `<div class="t-mini">${esc(r.found_in||'')}</div>`,
      `<code>${esc(r.line ?? '')}</code>`
    ]);
    cards += card('URLs/Rutas detectadas (posibles páginas)',
      `
      <div class="controls">
        <input id="routesSearch" class="search" placeholder="Buscar en rutas/URLs...">
      </div>
      <p class="muted">Mostrando <span id="routesCount">${Math.min(routes.length,180)}</span> de ${routes.length}.</p>
      <div id="routesTable">${table(['Path','Full URL','Found in','Line'], rows)}</div>
      `,'full'
    );
  }

  // Requests inferred (with search)
  const reqs = (RESULTS.endpoints && RESULTS.endpoints.requests_inferred) ? RESULTS.endpoints.requests_inferred : [];
  if(reqs.length){
    const rows = reqs.slice(0,200).map(x => [
      '',
      `<div class="badges">${badge((x.method||'UNKNOWN').toUpperCase(),'blue')}</div>`,
      `<a href="${esc(x.full_url||'')}" target="_blank">${esc(x.full_url||'')}</a>`,
      `<div class="badges">${(x.params||[]).length ? (x.params||[]).map(p=>badge(p,'gray')).join('') : badge('—','gray')}</div>`,
      `<div class="badges">${(x.body_keys||[]).length ? (x.body_keys||[]).map(p=>badge(p,'gray')).join('') : badge('—','gray')}</div>`,
      `<div class="t-mini">${esc(x.evidence||'')}</div>`,
      `<div class="t-mini">${esc(x.found_in||'')} : ${esc(x.line||'')}</div>`
    ]);
    cards += card('Requests inferidos (método + endpoint + hints)',
      `
      <div class="controls">
        <input id="reqSearch" class="search" placeholder="Buscar en requests/endpoints...">
      </div>
      <p class="muted">Mostrando <span id="reqCount">${Math.min(reqs.length,200)}</span> de ${reqs.length}.</p>
      <div id="reqTable">${table(['', 'Method','Full URL','Params','Body keys','Evidence','Found in'], rows)}</div>
      `,'full'
    );
  }

  // Gallery (screenshots routes)
  const shots = (RESULTS.screenshots && RESULTS.screenshots.routes) ? RESULTS.screenshots.routes : [];
  if(shots.length){
    const tiles = shots.map(it=>{
      const url = it.url || '';
      const path = it.path || '';
      const kind = it.kind || 'route';
      return `
        <a class="tile" href="${esc(path)}" target="_blank" rel="noreferrer" data-url="${esc(url)}" data-kind="${esc(kind)}">
          <div class="tile-top">
            <span class="chip">${esc(kind)}</span>
          </div>
          <img class="thumb" src="${esc(path)}" alt="shot"/>
          <div class="tile-bot">
            <div class="t-url">${esc(url)}</div>
            <div class="t-meta">${esc(path)}</div>
          </div>
        </a>`;
    }).join('');

    cards += card('Galería de screenshots (rutas)',
      `<div class="controls">
        <input id="galSearch" class="search" placeholder="Filtrar por URL...">
      </div>
      <p class="muted">Mostrando <span id="galCount">${shots.length}</span> items.</p>
      <div class="gal-grid" id="galGrid">${tiles}</div>`,'full'
    );
  }

  // Notes
  const notes = RESULTS.notes || [];
  if(notes.length){
    cards += card('Notas', `<ul>${notes.slice(0,120).map(x=>`<li>${esc(x)}</li>`).join('')}</ul>`);
  }

  const filesCard = card('Archivos generados',
    `<p class="muted">Revisa el JSON para detalle completo.</p>
     <div class="badges">
       ${badge('results.json')} ${badge('index.html')} ${badge('report.template.html')}
       ${badge('routes/*.txt')} ${badge('screens/*.png')}
     </div>`
  );

  app.innerHTML = header + statsHtml + `<div class="grid">${cards}${filesCard}</div>` + `<footer>Darkmoon • Security Reporting</footer>`;

  // AuthZ filters
  const authSearch = document.getElementById('authSearch');
  const authCount = document.getElementById('authCount');
  const authTable = document.getElementById('authTable');
  let authActive = 'all';

  function authApply(){
    if(!authTable) return;
    const q = (authSearch && authSearch.value ? authSearch.value : '').toLowerCase();
    const rows = authTable.querySelectorAll('tbody tr');
    let shown = 0;
    rows.forEach(tr=>{
      const text = tr.innerText.toLowerCase();
      const hasAccess = text.includes('con acceso');
      const hasNo = text.includes('sin acceso');
      const has401 = text.includes('401');
      const has403 = text.includes('403');
      const has404 = text.includes('404');

      const okFilter =
        authActive === 'all' ||
        (authActive === 'access' && hasAccess) ||
        (authActive === 'noaccess' && hasNo) ||
        (authActive === '401' && has401) ||
        (authActive === '403' && has403) ||
        (authActive === '404' && has404);

      const okSearch = !q || text.includes(q);
      const ok = okFilter && okSearch;
      tr.style.display = ok ? '' : 'none';
      if(ok) shown++;
    });
    if(authCount) authCount.textContent = String(shown);
  }

  document.querySelectorAll('.fbtn').forEach(b=>{
    b.addEventListener('click', ()=>{
      document.querySelectorAll('.fbtn').forEach(x=>x.classList.remove('active'));
      b.classList.add('active');
      authActive = b.getAttribute('data-filter') || 'all';
      authApply();
    });
  });
  if(authSearch) authSearch.addEventListener('input', authApply);
  authApply();

  // Gallery filter
  const galGrid = document.getElementById('galGrid');
  const galSearch = document.getElementById('galSearch');
  const galCount = document.getElementById('galCount');

  function galApply(){
    if(!galGrid) return;
    const q = (galSearch && galSearch.value ? galSearch.value : '').toLowerCase();
    const tiles = galGrid.querySelectorAll('.tile');
    let shown = 0;
    tiles.forEach(t=>{
      const url = (t.getAttribute('data-url') || '').toLowerCase();
      const ok = !q || url.includes(q);
      t.style.display = ok ? '' : 'none';
      if(ok) shown++;
    });
    if(galCount) galCount.textContent = String(shown);
  }
  if(galSearch) galSearch.addEventListener('input', galApply);
  galApply();

  // Generic table searches
  wireTableSearch('routesSearch', 'routesTable', 'routesCount');
  wireTableSearch('reqSearch', 'reqTable', 'reqCount');
  wireTableSearch('beSearch', 'beTable', 'beCount');
}

build();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
