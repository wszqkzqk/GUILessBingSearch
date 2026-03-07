#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2026 Zhou Qiankang <wszqkzqk@qq.com>
#
# This file is part of GUI-Less Bing Search.
#
# GUI-Less Bing Search is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# GUI-Less Bing Search is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GUI-Less Bing Search. If not, see <https://www.gnu.org/licenses/>.

"""GUI-Less Bing Search.

A tool for accessing search results in environments without a
graphical user interface, using Qt6 WebEngine (PySide6) as a headless
Chromium browser engine.  Runs without GPU or display.

Supports Bing and DuckDuckGo search engines.

Disclaimer: This tool is intended strictly for manual, interactive use via
command-line interfaces (CLI) by individual users. It is not designed,
authorized, or intended for automated scraping, bulk data extraction, or
any high-frequency programmatic access.

Usage:
    python guiless_bing_search.py [--port 8765] [--host 127.0.0.1] [--api-key KEY]
"""

import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault(
    "QTWEBENGINE_CHROMIUM_FLAGS",
    "--disable-gpu --disable-software-rasterizer",
)

import argparse
import base64
import json
import logging
import platform
import queue
import random
import re
import signal
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, quote_plus, urlparse

from PySide6.QtCore import QUrl, QTimer, QObject
from PySide6.QtNetwork import QNetworkCookie
from PySide6.QtWebEngineCore import (
    QWebEnginePage,
    QWebEngineProfile,
    QWebEngineScript,
    QWebEngineSettings,
)
from PySide6.QtWidgets import QApplication

_VENDOR_ID = "io.github.wszqkzqk"
_APP_NAME = "guiless-bing-search"

BING_ENSEARCH = os.environ.get("BING_ENSEARCH", "").strip()
BING_BASE_URL = os.environ.get(
    "BING_BASE_URL", "https://www.bing.com",
).rstrip("/")
BING_U_COOKIE = os.environ.get("BING_U_COOKIE", "")
BING_EXTRA_COOKIES = os.environ.get("BING_EXTRA_COOKIES", "")
USER_AGENT = os.environ.get("USER_AGENT", "")
API_KEY = os.environ.get("API_KEY", "")

# Search engine selection: "bing" or "duckduckgo"
SEARCH_ENGINE = os.environ.get("SEARCH_ENGINE", "bing").strip().lower()

# Ordered fallback engines, comma-separated. When empty, a default fallback
# is derived automatically from the primary engine.
SEARCH_FALLBACK_ENGINES = os.environ.get(
    "SEARCH_FALLBACK_ENGINES", "",
).strip().lower()

# Minimum seconds between consecutive searches (0 = no limit).
# A random jitter of 0~50% is added on top to avoid causing concentrated access pressure on the server.
SEARCH_INTERVAL = float(os.environ.get("SEARCH_INTERVAL", "1"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("bing-search")

_CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]")

# PySide6 runJavaScript cannot marshal JS objects directly;
# we JSON.stringify on the JS side instead.
_EXTRACT_JS = """\
(function() {
    var results = [];
    document.querySelectorAll('li.b_algo').forEach(function(li) {
        var a = li.querySelector('h2 a');
        if (!a || !a.href) return;
        var p = li.querySelector('.b_caption p') ||
                li.querySelector('.b_lineclamp') ||
                li.querySelector('.b_algoSlug');
        results.push({
            link: a.href,
            title: (a.textContent || '').trim(),
            snippet: p ? (p.textContent || '').trim() : ''
        });
    });
    return JSON.stringify(results);
})()
"""

_DDG_EXTRACT_JS = """\
(function() {
    var results = [];
    // DuckDuckGo new layout
    document.querySelectorAll('article[data-testid="result"]').forEach(function(art) {
        var a = art.querySelector('a[data-testid="result-title-a"]') || art.querySelector('a');
        if (!a || !a.href || !a.href.startsWith('http')) return;
        var snippetEl = art.querySelector('div[data-result="snippet"]') || art.querySelector('.E2eLOJWyd02pBqxzLcdl');
        results.push({
            link: a.href,
            title: (a.textContent || '').trim(),
            snippet: snippetEl ? (snippetEl.textContent || '').trim() : ''
        });
    });
    // DuckDuckGo old fallback
    if (results.length === 0) {
        document.querySelectorAll('.result__body').forEach(function(div) {
            var a = div.querySelector('.result__a');
            if (!a || !a.href) return;
            var snippetEl = div.querySelector('.result__snippet');
            results.push({
                link: a.href,
                title: (a.textContent || '').trim(),
                snippet: snippetEl ? (snippetEl.textContent || '').trim() : ''
            });
        });
    }
    return JSON.stringify(results);
})()
"""

# Normalize screen dimensions and chrome object for offscreen mode.
_BROWSER_INIT_JS = """\
Object.defineProperty(navigator, 'webdriver', {get: () => false});

var _W = 1920, _H = 1080;
['width','availWidth'].forEach(function(k){
    Object.defineProperty(screen, k, {get: () => _W});
});
['height','availHeight'].forEach(function(k){
    Object.defineProperty(screen, k, {get: () => _H});
});
Object.defineProperty(screen, 'colorDepth', {get: () => 24});
Object.defineProperty(screen, 'pixelDepth', {get: () => 24});

Object.defineProperty(window, 'outerWidth',  {get: () => _W});
Object.defineProperty(window, 'outerHeight', {get: () => _H});
Object.defineProperty(window, 'innerWidth',  {get: () => _W});
Object.defineProperty(window, 'innerHeight', {get: () => _H - 80});
Object.defineProperty(window, 'devicePixelRatio', {get: () => 1});

if (!window.chrome) window.chrome = {};
if (!window.chrome.runtime) {
    window.chrome.runtime = {connect: function(){}, sendMessage: function(){}};
}
if (!window.chrome.app) window.chrome.app = {isInstalled: false};
"""


class _SearchRequest:
    __slots__ = ("query", "count", "results", "done")

    def __init__(self, query: str, count: int):
        self.query = query
        self.count = count
        self.results: list[dict] = []
        self.done = threading.Event()


_engine_queues: dict[str, queue.Queue[_SearchRequest]] = {
    "bing": queue.Queue(),
    "duckduckgo": queue.Queue(),
}


def _has_chinese(text: str) -> bool:
    return bool(_CJK_RE.search(text))


def _resolve_ensearch(query: str) -> tuple[str, str]:
    """Return (ensearch_url_value, mode_label).

    Returns "1" for international or "" for domestic (real browsers
    never send ensearch=0, they simply omit the parameter).
    Auto mode: CJK queries -> domestic, otherwise -> international.
    """
    if BING_ENSEARCH == "1":
        return "1", "intl/forced"
    if BING_ENSEARCH == "0":
        return "", "local/forced"
    # Auto: international for non-CJK, domestic for CJK
    if _has_chinese(query):
        return "", "local/auto"
    return "1", "intl/auto"


def _decode_bing_redirect(url: str) -> str:
    """Decode Bing's /ck/a redirect URLs to the actual target.
    This is done to allow users to copy and paste the actual target URL
    directly from the CLI output, rather than having to go through Bing's
    redirect tracker which might not work well in headless environments.
    Additionally, this acts as a privacy-enhancing feature by preventing
    the search engine from tracking which specific results the user clicks.
    """
    try:
        parsed = urlparse(url)
        if parsed.hostname not in (
            "www.bing.com", "bing.com", "cn.bing.com",
        ):
            return url
        if parsed.path != "/ck/a":
            return url
        qs = parse_qs(parsed.query)
        u_vals = qs.get("u")
        if not u_vals or not u_vals[0].startswith("a1"):
            return url
        encoded = u_vals[0][2:]
        padded = encoded + "=" * (-len(encoded) % 4)
        decoded = base64.urlsafe_b64decode(padded).decode(
            "utf-8", errors="replace",
        )
        if decoded.startswith("http"):
            return decoded
    except Exception:
        pass
    return url


def _decode_ddg_redirect(url: str) -> str:
    """Decode DuckDuckGo's //duckduckgo.com/l/ redirect URLs."""
    try:
        parsed = urlparse(url)
        if parsed.hostname and "duckduckgo" not in parsed.hostname:
            return url
        if "/l/" not in parsed.path:
            return url
        qs = parse_qs(parsed.query)
        uddg = qs.get("uddg")
        if uddg and uddg[0].startswith("http"):
            return uddg[0]
    except Exception:
        pass
    return url


def _parse_js(data) -> list[dict]:
    if isinstance(data, str) and data:
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            pass
    if isinstance(data, list):
        return data
    return []


def _default_profile_dir() -> str:
    """Return platform-appropriate user data directory for this app.

    When running under systemd with StateDirectory=, the STATE_DIRECTORY
    environment variable is set automatically and takes precedence.
    """
    state_dir = os.environ.get("STATE_DIRECTORY")
    if state_dir:
        return state_dir
    s = platform.system()
    if s == "Windows":
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
    elif s == "Darwin":
        base = os.path.join(
            os.path.expanduser("~"), "Library", "Application Support",
        )
    else:
        base = os.environ.get(
            "XDG_DATA_HOME",
            os.path.join(os.path.expanduser("~"), ".local", "share"),
        )
    return os.path.join(base, _VENDOR_ID, _APP_NAME)


class _BaseSearchEngine(QObject):
    """Base class for headless search engines using QWebEnginePage."""

    # Subclasses must set these.
    _EXTRACT_JS: str = ""
    _PROBE_SELECTOR: str = ""

    _MAX_POLLS = 10
    _POLL_MS = 200

    def __init__(self, profile: QWebEngineProfile, engine_name: str):
        super().__init__()
        self._engine_name_value = engine_name
        self._page = QWebEnginePage(profile, self)
        self._page.settings().setAttribute(
            QWebEngineSettings.WebAttribute.AutoLoadImages, False,
        )
        self._page.settings().setAttribute(
            QWebEngineSettings.WebAttribute.PluginsEnabled, False,
        )

        script = QWebEngineScript()
        script.setSourceCode(_BROWSER_INIT_JS)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        script.setInjectionPoint(
            QWebEngineScript.InjectionPoint.DocumentCreation,
        )
        script.setRunsOnSubFrames(True)
        self._page.scripts().insert(script)

        self._current: _SearchRequest | None = None
        self._last_search_time: float = 0.0

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._poll)
        self._timer.start(50)

    def _poll(self):
        if self._current is not None:
            return
        try:
            self._current = _engine_queues[self._engine_name_value].get_nowait()
        except queue.Empty:
            return

        if SEARCH_INTERVAL > 0:
            elapsed = time.monotonic() - self._last_search_time
            jitter = random.uniform(0, SEARCH_INTERVAL * 0.5)
            required = SEARCH_INTERVAL + jitter
            if elapsed < required:
                delay_ms = int((required - elapsed) * 1000)
                QTimer.singleShot(delay_ms, self._start_search)
                return

        self._start_search()

    def _start_search(self):
        assert self._current is not None
        self._last_search_time = time.monotonic()
        log.info("Searching [%s]: '%s'", self._engine_name(), self._current.query)
        self._navigate()

    def _engine_name(self) -> str:
        return self._engine_name_value

    def _navigate(self):
        """Subclasses must implement to build URL and load the page."""
        raise NotImplementedError

    def _on_loaded(self, ok: bool):
        self._page.loadFinished.disconnect(self._on_loaded)
        if not ok:
            log.warning("Page load failed")
            self._finish([])
            return
        log.info("Page loaded: %s", self._page.url().toString())
        self._poll_count = 0
        QTimer.singleShot(200, self._probe)

    def _probe(self):
        self._poll_count += 1
        probe_js = f"document.querySelectorAll('{self._PROBE_SELECTOR}').length"
        self._page.runJavaScript(probe_js, 0, self._on_probe)

    def _on_probe(self, n):
        n = int(n) if n else 0
        if n > 0:
            self._extract()
        elif self._poll_count < self._MAX_POLLS:
            QTimer.singleShot(self._POLL_MS, self._probe)
        else:
            log.warning("No results after %d polls, extracting anyway",
                        self._poll_count)
            self._extract()

    def _extract(self):
        self._page.runJavaScript(self._EXTRACT_JS, 0, self._on_results)

    def _on_results(self, data):
        assert self._current is not None
        results = _parse_js(data)
        results = self._decode_redirects(results)
        self._finish(results[: self._current.count])

    def _decode_redirects(self, results: list[dict]) -> list[dict]:
        """Subclasses can override to decode engine-specific redirect URLs."""
        return results

    def _finish(self, results: list[dict]):
        assert self._current is not None
        req = self._current
        self._current = None
        req.results = results
        req.done.set()
        log.info(
            "Query '%s' -> %d results [%s]",
            req.query, len(results), self._engine_name(),
        )
        for i, r in enumerate(results, 1):
            log.info(
                "  [%d] %s | %s",
                i, r.get("title", ""), r.get("link", ""),
            )


class BingEngine(_BaseSearchEngine):
    """Navigate to Bing search URLs and extract results via QWebEnginePage."""

    _EXTRACT_JS = _EXTRACT_JS
    _PROBE_SELECTOR = "li.b_algo"

    def _navigate(self):
        assert self._current is not None
        q = quote_plus(self._current.query)
        ensearch_param, mode = _resolve_ensearch(self._current.query)
        # FORM codes from Bing's homepage: QBLHCN (intl), QBLH (domestic).
        form_code = "QBLHCN" if ensearch_param == "1" else "QBLH"
        params = [f"q={q}", f"FORM={form_code}"]
        if ensearch_param:
            params.append(f"ensearch={ensearch_param}")
        url = f"{BING_BASE_URL}/search?{'&'.join(params)}"
        log.info("navigate %s (%s)", url, mode)
        self._page.loadFinished.connect(self._on_loaded)
        self._page.load(QUrl(url))

    def _decode_redirects(self, results: list[dict]) -> list[dict]:
        for r in results:
            if "link" in r:
                r["link"] = _decode_bing_redirect(r["link"])
        return results


class DuckDuckGoEngine(_BaseSearchEngine):
    """Navigate to DuckDuckGo search URLs and extract results."""

    _EXTRACT_JS = _DDG_EXTRACT_JS
    _PROBE_SELECTOR = 'article[data-testid="result"]'

    _MAX_POLLS = 15  # DDG may need more time for JS rendering

    def _navigate(self):
        assert self._current is not None
        q = quote_plus(self._current.query)
        url = f"https://duckduckgo.com/?q={q}&ia=web"
        log.info("navigate %s", url)
        self._page.loadFinished.connect(self._on_loaded)
        self._page.load(QUrl(url))

    def _probe(self):
        """DuckDuckGo uses JS-heavy rendering; also check fallback selector."""
        self._poll_count += 1
        probe_js = (
            "(document.querySelectorAll('article[data-testid=\"result\"]').length"
            " || document.querySelectorAll('.result').length)"
        )
        self._page.runJavaScript(probe_js, 0, self._on_probe)

    def _decode_redirects(self, results: list[dict]) -> list[dict]:
        for r in results:
            if "link" in r:
                r["link"] = _decode_ddg_redirect(r["link"])
        return results


_ENGINE_CLASSES = {
    "bing": BingEngine,
    "duckduckgo": DuckDuckGoEngine,
}


def _normalize_engine_name(engine_name: str) -> str:
    engine_name = engine_name.strip().lower()
    if engine_name == "ddg":
        return "duckduckgo"
    return engine_name


def _default_fallback_engines(primary_engine: str) -> list[str]:
    if primary_engine == "bing":
        return ["duckduckgo"]
    if primary_engine == "duckduckgo":
        return ["bing"]
    return []


def _resolve_engine_chain(
    primary_engine: str, fallback_engines: list[str] | None = None,
) -> list[str]:
    chain: list[str] = []
    candidates = [_normalize_engine_name(primary_engine)]
    if fallback_engines is None:
        configured = [
            value.strip() for value in SEARCH_FALLBACK_ENGINES.split(",")
            if value.strip()
        ]
        candidates.extend(configured or _default_fallback_engines(candidates[0]))
    else:
        candidates.extend(fallback_engines)

    for candidate in candidates:
        engine_name = _normalize_engine_name(candidate)
        if engine_name not in _ENGINE_CLASSES:
            log.warning("Ignoring unsupported engine in chain: %s", candidate)
            continue
        if engine_name not in chain:
            chain.append(engine_name)
    return chain


def _scrape_once(engine_name: str, query: str, count: int) -> list[dict]:
    req = _SearchRequest(query, count)
    _engine_queues[engine_name].put(req)
    if not req.done.wait(timeout=30):
        log.warning("Search timed out [%s]: '%s'", engine_name, query)
        return []
    return req.results


def scrape_search(
    query: str,
    count: int = 10,
    primary_engine: str | None = None,
    fallback_engines: list[str] | None = None,
) -> list[dict]:
    """Search using the primary engine, then fall back on empty results."""
    engine_chain = _resolve_engine_chain(primary_engine or SEARCH_ENGINE,
                                         fallback_engines)
    if not engine_chain:
        log.warning("No valid search engines configured")
        return []

    for index, engine_name in enumerate(engine_chain, start=1):
        log.info("Dispatching query to engine %d/%d: %s",
                 index, len(engine_chain), engine_name)
        results = _scrape_once(engine_name, query, count)
        if results:
            if index > 1:
                log.info("Fallback succeeded with engine: %s", engine_name)
            return results
        if index < len(engine_chain):
            log.warning("Engine %s returned no results, trying fallback",
                        engine_name)
    return []


def scrape_bing(query: str, count: int = 10) -> list[dict]:
    return scrape_search(query, count, primary_engine="bing",
                         fallback_engines=["duckduckgo"])


class SearchHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.info(fmt, *args)

    def _check_auth(self) -> bool:
        """Validate Bearer token if API_KEY is configured.

        Returns True if the request is authorized.
        When API_KEY is empty (default), all requests are allowed.
        """
        if not API_KEY:
            return True
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:].strip()
            if token == API_KEY:
                return True
        self._send_json({"error": "unauthorized"}, 401)
        return False

    def _send_json(self, data, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send_json({"status": "ok"})
        else:
            if not self._check_auth():
                return
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        if not self._check_auth():
            return
        if self.path != "/search":
            self._send_json({"error": "not found"}, 404)
            return
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            self._send_json({"error": "empty body"}, 400)
            return
        try:
            body = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._send_json({"error": "invalid JSON"}, 400)
            return
        query = body.get("query", "").strip()
        count = body.get("count", 5)
        engine = _normalize_engine_name(body.get("engine", SEARCH_ENGINE))
        fallback = body.get("fallback_engines")
        if not query:
            self._send_json({"error": "query is required"}, 400)
            return
        if not isinstance(count, int) or count < 1:
            count = 5
        count = min(count, 30)
        if fallback is None:
            fallback_engines = None
        elif isinstance(fallback, list):
            fallback_engines = [str(item) for item in fallback]
        elif isinstance(fallback, str):
            fallback_engines = [
                item.strip() for item in fallback.split(",") if item.strip()
            ]
        else:
            self._send_json(
                {"error": "fallback_engines must be a string or list"}, 400,
            )
            return
        log.info("Request: query='%s', count=%d, engine=%s",
                 query, count, engine)
        log.info("Request headers:\n%s", self.headers)
        results = scrape_search(query, count, engine, fallback_engines)
        self._send_json(results)


def _inject_cookies(
    profile: QWebEngineProfile, engine_name: str,
) -> None:
    """Inject engine-specific cookies into the cookie store."""
    cookies: dict[str, str] = {}
    domain = ".bing.com"

    if engine_name == "bing":
        if BING_U_COOKIE:
            cookies["_U"] = BING_U_COOKIE
        if BING_EXTRA_COOKIES:
            try:
                extra = json.loads(BING_EXTRA_COOKIES)
                if isinstance(extra, dict):
                    cookies.update(extra)
            except json.JSONDecodeError:
                log.warning("BING_EXTRA_COOKIES is not valid JSON, ignored")
    elif engine_name == "duckduckgo":
        domain = ".duckduckgo.com"

    store = profile.cookieStore()
    for name, value in cookies.items():
        c = QNetworkCookie(name.encode(), value.encode())
        c.setDomain(domain)
        c.setPath("/")
        c.setSecure(True)
        store.setCookie(c)


def _build_profile(
    app: QApplication, profile_dir: str = "", engine_name: str = "bing",
) -> QWebEngineProfile:
    """Create a persistent WebEngine profile with clean UA."""
    profile = QWebEngineProfile(f"{engine_name}-search", app)

    storage_root = profile_dir or _default_profile_dir()
    storage = os.path.join(storage_root, engine_name)
    os.makedirs(storage, exist_ok=True)
    profile.setPersistentStoragePath(storage)
    profile.setCachePath(os.path.join(storage, "cache"))

    if USER_AGENT:
        profile.setHttpUserAgent(USER_AGENT)

    profile.setPersistentCookiesPolicy(
        QWebEngineProfile.PersistentCookiesPolicy.AllowPersistentCookies,
    )
    log.info("UA: %s", profile.httpUserAgent())
    log.info("Profile: %s", profile.persistentStoragePath())
    return profile


def main():
    parser = argparse.ArgumentParser(
        description="GUI-Less Search (Bing / DuckDuckGo)",
    )
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("PORT", "8765")),
    )
    parser.add_argument(
        "--engine", default=None,
        choices=["bing", "duckduckgo", "ddg"],
        help="Search engine to use (default: bing)",
    )
    parser.add_argument(
        "--fallback-engines", default=None,
        help="Comma-separated fallback engines (default: auto)",
    )
    parser.add_argument(
        "--u-cookie", default=None,
        help="Set _U cookie for Bing",
    )
    parser.add_argument(
        "--base-url", default=None,
        help="Bing base URL (default: https://www.bing.com)",
    )
    parser.add_argument(
        "--profile-dir", default=None,
        help="Custom profile directory (portable between machines)",
    )
    parser.add_argument(
        "--search-interval", type=float, default=None,
        help="Minimum seconds between searches (default: 1)",
    )
    parser.add_argument(
        "--api-key", default=None,
        help="API key for Bearer token authentication (optional)",
    )
    args = parser.parse_args()

    global BING_U_COOKIE, BING_BASE_URL, SEARCH_INTERVAL, API_KEY
    global SEARCH_ENGINE, SEARCH_FALLBACK_ENGINES
    if args.u_cookie:
        BING_U_COOKIE = args.u_cookie
    if args.base_url:
        BING_BASE_URL = args.base_url.rstrip("/")
    if args.search_interval is not None:
        SEARCH_INTERVAL = args.search_interval
    if args.api_key is not None:
        API_KEY = args.api_key
    if args.engine is not None:
        SEARCH_ENGINE = _normalize_engine_name(args.engine)
    if args.fallback_engines is not None:
        SEARCH_FALLBACK_ENGINES = args.fallback_engines

    if SEARCH_ENGINE not in _ENGINE_CLASSES:
        log.error(
            "Unknown engine '%s'. Choose from: %s",
            SEARCH_ENGINE, ", ".join(_ENGINE_CLASSES),
        )
        sys.exit(1)

    # Ensure XDG_DATA_HOME points to a writable directory before
    # QApplication / QWebEngineProfile constructors try to create
    # their default storage paths.  Under systemd DynamicUser=yes the
    # home is "/" and ~/.local/share is not writable.
    _storage = args.profile_dir or _default_profile_dir()
    os.makedirs(_storage, exist_ok=True)
    if "XDG_DATA_HOME" not in os.environ:
        os.environ["XDG_DATA_HOME"] = _storage

    app = QApplication(sys.argv)
    app.setApplicationName(_APP_NAME)

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: app.quit())
    _sig_timer = QTimer()
    _sig_timer.start(500)
    _sig_timer.timeout.connect(lambda: None)

    engines = []
    for engine_name in _resolve_engine_chain(SEARCH_ENGINE):
        profile = _build_profile(app, _storage, engine_name)
        _inject_cookies(profile, engine_name)
        engine_cls = _ENGINE_CLASSES[engine_name]
        engines.append(engine_cls(profile, engine_name))

    server = HTTPServer((args.host, args.port), SearchHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    log.info("Listening on http://%s:%d", args.host, args.port)
    log.info(
        "  engine: %s, fallback: %s, interval: %.1fs, auth: %s",
        SEARCH_ENGINE,
        ",".join(_resolve_engine_chain(SEARCH_ENGINE)[1:]) or "none",
        SEARCH_INTERVAL,
        "enabled" if API_KEY else "disabled",
    )
    if SEARCH_ENGINE == "bing":
        log.info(
            "  ensearch: %s",
            {"1": "intl", "0": "local"}.get(BING_ENSEARCH, "auto"),
        )

    try:
        app.exec()
    finally:
        server.shutdown()
        server.server_close()
        log.info("Shutdown complete")


if __name__ == "__main__":
    main()
