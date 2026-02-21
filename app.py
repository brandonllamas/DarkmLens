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
                "configs_parsed": [],
                "firestore_rest": [],
                "rtdb": [],
                "collections_probable": [],
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
            m = re.search(rf'["\']?{key}["\']?\s*[:=]\s*["\']([^"\']+)["\']', blob, re.IGNORECASE)
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
                parsed = self._parse_firebase_config(blob)
                if parsed:
                    self.add_finding(self.results["firebase"]["configs_parsed"], {"fields": parsed, "found_in": source_name, "line": ln})

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

            # Classify each route as frontend or backend
            for r in self.results["inventory"]["routes_full_urls"]:
                if "route_type" not in r:
                    r["route_type"] = self._classify_route_type(r.get("path") or "/")

        # Build app stack summary
        self._identify_app_stack()

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

  <!-- SCREENSHOT GALLERY -->
  ${buildGallery()}

  <!-- NOTES -->
  ${buildNotes()}

  <footer>
    <b>DarkmLens</b> · Darkmoon Security Reporting · Uso autorizado únicamente
  </footer>
  `;

  /* wire searches */
  wireSearch('feSearch','feTable','feCount');
  wireSearch('beSearch','beTable','beCount');
  wireSearch('reqSearch','reqTable','reqCount');
  wireSearch('authSearch','authTable','authCount');

  /* authz filters */
  setupAuthzFilters();

  /* gallery filter */
  setupGalleryFilter();
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

build();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
