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

A tool for accessing Bing search results in environments without a
graphical user interface, using Playwright as a headless
Chromium browser engine.  Runs without GPU or display.

Disclaimer: This tool is intended strictly for manual, interactive use via
command-line interfaces (CLI) by individual users. It is not designed,
authorized, or intended for automated scraping, bulk data extraction, or
any high-frequency programmatic access.

Usage:
    python guiless_bing_search.py [--port 8765] [--host 127.0.0.1] [--api-key KEY]
"""

import argparse
import base64
import json
import logging
import os
import platform
import queue
import random
import re
import signal
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, quote_plus, urlparse

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

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

# Minimum seconds between consecutive searches (0 = no limit).
# A random jitter of 0~50% is added on top to avoid causing concentrated access pressure on the server.
SEARCH_INTERVAL = float(os.environ.get("SEARCH_INTERVAL", "1"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("bing-search")

_CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]")

# Playwright evaluate can return JS objects directly.
_EXTRACT_JS = """\
() => {
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
    return results;
}
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


_search_queue: queue.Queue[_SearchRequest] = queue.Queue()


def _has_chinese(text: str) -> bool:
    return bool(_CJK_RE.search(text))


def _resolve_ensearch(query: str) -> tuple[str, str]:
    """Return (ensearch_value, mode) based on config or CJK content.

    ensearch=1 (international) is used for non-CJK queries,
    ensearch=0 (domestic) for CJK queries, unless overridden.
    """
    if BING_ENSEARCH == "1":
        return "1", "forced"
    if BING_ENSEARCH == "0":
        return "0", "forced"
    if _has_chinese(query):
        return "0", "auto"
    return "1", "auto"


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


def scrape_bing(query: str, count: int = 10) -> list[dict]:
    """Enqueue a search request and block until results are ready."""
    req = _SearchRequest(query, count)
    _search_queue.put(req)
    if not req.done.wait(timeout=30):
        log.warning("Search timed out: '%s'", query)
    return req.results


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
        if not query:
            self._send_json({"error": "query is required"}, 400)
            return
        if not isinstance(count, int) or count < 1:
            count = 5
        count = min(count, 30)
        log.info("Request: query='%s', count=%d", query, count)
        results = scrape_bing(query, count)
        self._send_json(results)


def _run_playwright_worker(profile_dir: str):
    last_search_time = 0.0
    
    with sync_playwright() as p:
        # Prepare cookies
        cookies = []
        if BING_U_COOKIE:
            cookies.append({
                "name": "_U",
                "value": BING_U_COOKIE,
                "domain": ".bing.com",
                "path": "/",
                "secure": True
            })
        if BING_EXTRA_COOKIES:
            try:
                extra = json.loads(BING_EXTRA_COOKIES)
                if isinstance(extra, dict):
                    for k, v in extra.items():
                        cookies.append({
                            "name": k,
                            "value": v,
                            "domain": ".bing.com",
                            "path": "/",
                            "secure": True
                        })
            except json.JSONDecodeError:
                log.warning("BING_EXTRA_COOKIES is not valid JSON, ignored")

        # Launch browser
        launch_args = {
            "user_data_dir": profile_dir,
            "headless": True,
            "args": ["--disable-gpu", "--disable-software-rasterizer"],
        }
        if USER_AGENT:
            launch_args["user_agent"] = USER_AGENT
            
        context = p.chromium.launch_persistent_context(**launch_args)
        
        if cookies:
            context.add_cookies(cookies)
            
        page = context.new_page()
        page.add_init_script(_BROWSER_INIT_JS)
        
        # Block unnecessary resources to speed up loading
        page.route("**/*", lambda route: route.abort() if route.request.resource_type in ["image", "media", "font", "stylesheet"] else route.continue_())

        # Check if we need to login to Bing to avoid failures caused by redirects in China.
        if os.environ.get("BING_LOGIN_EMAIL") and os.environ.get("BING_LOGIN_PASSWORD"):
            log.info("Attempting to login to Bing...")
            try:
                page.goto("https://login.live.com/", wait_until="domcontentloaded", timeout=15000)
                page.fill("input[type='email']", os.environ.get("BING_LOGIN_EMAIL"))
                page.click("input[type='submit']")
                page.wait_for_selector("input[type='password']", timeout=5000)
                page.fill("input[type='password']", os.environ.get("BING_LOGIN_PASSWORD"))
                page.click("input[type='submit']")
                try:
                    page.wait_for_selector("input[id='idBtn_Back']", timeout=5000)
                    page.click("input[id='idBtn_Back']")
                except PlaywrightTimeoutError:
                    pass
                log.info("Login successful.")
            except Exception as e:
                log.error("Login failed: %s", e)

        log.info("Playwright worker started. UA: %s", page.evaluate("navigator.userAgent"))
        log.info("Profile: %s", profile_dir)

        while True:
            try:
                req = _search_queue.get(timeout=1.0)
            except queue.Empty:
                continue
                
            if req is None:
                break
                
            # Enforce interval
            if SEARCH_INTERVAL > 0:
                elapsed = time.monotonic() - last_search_time
                jitter = random.uniform(0, SEARCH_INTERVAL * 0.5)
                required = SEARCH_INTERVAL + jitter
                if elapsed < required:
                    time.sleep(required - elapsed)
                    
            last_search_time = time.monotonic()
            log.info("Searching: '%s'", req.query)
            
            q = quote_plus(req.query)
            ensearch_val, mode = _resolve_ensearch(req.query)
            params = [f"q={q}"]
            if ensearch_val:
                params.append(f"ensearch={ensearch_val}")
            url = f"{BING_BASE_URL}/search?{'&'.join(params)}"
            
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=15000)
                # Wait for results to appear
                try:
                    page.wait_for_selector("li.b_algo", timeout=5000)
                except PlaywrightTimeoutError:
                    log.warning("Timeout waiting for search results selector")
                    
                results = page.evaluate(_EXTRACT_JS)
                
                for r in results:
                    if "link" in r:
                        r["link"] = _decode_bing_redirect(r["link"])
                        
                req.results = results[:req.count]
                
                tag = {"1": "intl", "0": "local"}.get(ensearch_val, "default")
                log.info(
                    "Query '%s' -> %d results (%s, %s)",
                    req.query, len(req.results), tag, mode,
                )
            except Exception as e:
                log.error("Search failed: %s", e)
                req.results = []
            finally:
                req.done.set()
                
        context.close()


def main():
    parser = argparse.ArgumentParser(
        description="GUI-Less Bing Search",
    )
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("PORT", "8765")),
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
    if args.u_cookie:
        BING_U_COOKIE = args.u_cookie
    if args.base_url:
        BING_BASE_URL = args.base_url.rstrip("/")
    if args.search_interval is not None:
        SEARCH_INTERVAL = args.search_interval
    if args.api_key is not None:
        API_KEY = args.api_key

    _storage = args.profile_dir or _default_profile_dir()
    os.makedirs(_storage, exist_ok=True)

    server = HTTPServer((args.host, args.port), SearchHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    log.info("Listening on http://%s:%d", args.host, args.port)
    log.info(
        "  ensearch: %s, interval: %.1fs, auth: %s",
        {"1": "intl", "0": "local"}.get(BING_ENSEARCH, "auto"),
        SEARCH_INTERVAL,
        "enabled" if API_KEY else "disabled",
    )

    def handle_sigterm(*_):
        log.info("Received shutdown signal")
        _search_queue.put(None)

    signal.signal(signal.SIGINT, handle_sigterm)
    signal.signal(signal.SIGTERM, handle_sigterm)

    try:
        _run_playwright_worker(_storage)
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)
        log.info("Shutdown complete")


if __name__ == "__main__":
    main()
