# GUI-Less Bing Search

An unofficial tool for accessing Bing search results in environments **without a graphical user interface**, built for personal study and research on headless information retrieval.

In many server, container, or embedded environments there is no desktop or browser available, yet users still need to look up information on the web. This tool wraps Playwright as a headless Chromium engine and exposes a minimal HTTP API so that users can query Bing via `curl` or similar command-line utilities.

Because no result links are fed back to Bing, the tool does not leak which results the user actually visited, offering a degree of privacy protection compared to using a regular browser.

**Disclaimer:** This tool is intended strictly for manual, interactive use via command-line interfaces (CLI) by individual users. It is not designed, authorized, or intended for automated scraping, bulk data extraction, or any high-frequency programmatic access. Any use of this tool for automated data collection or other purposes that violate the Terms of Service of the target search engine is strictly prohibited. The user assumes full responsibility for ensuring their use of this tool complies with all applicable laws and terms of service.

## Dependencies

- `python>=3.10.0`
- `python-playwright`

## Installation on Arch Linux

This package is available on the [AUR](https://aur.archlinux.org/packages/guiless-bing-search). You can install it with an AUR helper such as `paru` or `yay`:

```bash
paru -S guiless-bing-search
# or
yay -S guiless-bing-search
```

After installation, you can edit the configuration file (optional) and then enable the service:

```bash
sudo systemctl enable --now guiless-bing-search
```

The service listens on `127.0.0.1:8765` by default. You can then query it via `curl` as shown in [Usage Examples](#usage-examples).

## Quick Start

```bash
# Start the service (headless, no display needed)
python guiless_bing_search.py

# Custom profile directory
python guiless_bing_search.py --profile-dir /path/to/profile
```

## Usage Examples

Once the service is running, search Bing from the command line:

```bash
# Health check
curl http://localhost:8765/health

# Simple search
curl -s -X POST http://localhost:8765/search \
    -H "Content-Type: application/json" \
    -d '{"query": "Python tutorial"}' | python -m json.tool

# Limit the number of results
curl -s -X POST http://localhost:8765/search \
    -H "Content-Type: application/json" \
    -d '{"query": "Linux kernel", "count": 3}' | python -m json.tool
```

Response format:

```json
[
    {"link": "https://...", "title": "...", "snippet": "..."},
    ...
]
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `BING_ENSEARCH` | (auto) | For `https://cn.bing.com`.`1` = international, `0` = domestic (Chinese), unset = auto (by CJK detection) |
| `BING_BASE_URL` | `https://www.bing.com` | Base URL for Bing search |
| `HOST` | `127.0.0.1` | Listen address |
| `PORT` | `8765` | Listen port |
| `USER_AGENT` | (auto) | Custom User-Agent |
| `SEARCH_INTERVAL` | `1` | Minimum seconds between searches; random jitter of 0-50% is added automatically to avoid causing concentrated access pressure on the server |
| `BING_U_COOKIE` | (empty) | See [Cookie Troubleshooting](#cookie-troubleshooting) |
| `BING_EXTRA_COOKIES` | (empty) | Extra cookies as JSON, e.g. `{"MUID":"..."}` |
| `API_KEY` | (empty) | API key for `Bearer` token auth; if empty, no auth required |

## Command-Line Options

```
--host HOST           Listen address (default: 127.0.0.1)
--port PORT           Listen port (default: 8765)
--profile-dir DIR     Custom profile directory
--u-cookie COOKIE     Set _U cookie for Bing (see Cookie Troubleshooting)
--base-url URL        Bing base URL
--search-interval N   Minimum seconds between searches (default: 1)
--api-key KEY         API key for Bearer token auth (optional)
```

## Cookie Troubleshooting

In certain network environments (notably mainland China), accessing `bing.com` may involve complex redirects, which can leave the browser profile in a broken cookie state and cause searches to fail or return incorrect results.

If you experience this problem, try one of the following:

1. **Delete the profile directory** to start with a clean state.
2. **Set `BING_U_COOKIE`** or `BING_EXTRA_COOKIES` to supply known-good
   cookie values that resolve the redirect issue.

If your network can reach `bing.com` without issues, you do not need to
set any cookie variables.

## Profile Storage

By default, profile data (cookies, local storage) is stored under the
platform-appropriate user data directory:

| Platform | Path |
|---|---|
| Linux (User) | `$XDG_DATA_HOME/io.github.wszqkzqk/guiless-bing-search/` (typically `~/.local/share/...`) |
| Linux (systemd with `StateDirectory=`) | `/var/lib/io.github.wszqkzqk/guiless-bing-search/` (via `$STATE_DIRECTORY`) |
| macOS | `~/Library/Application Support/io.github.wszqkzqk/guiless-bing-search/` |
| Windows | `%LOCALAPPDATA%\io.github.wszqkzqk\guiless-bing-search\` |

Override with `--profile-dir` for portability.

## OpenWebUI Integration (For study and research purposes only)

While this tool is designed for manual CLI usage, its standard HTTP JSON interface means it *technically* can be connected to other local tools, such as [OpenWebUI](https://github.com/open-webui/open-webui) for study and research purpose such as debugging the format of search results.

> **⚠️ STRICT LIABILITY WARNING:** 
> 
> **The author explicitly disclaims any endorsement of using this tool as a LLM search backend.** Doing so may rapidly trigger anti-bot protections, result in IP/account bans, and violate the target search engine's **Terms of Service**.
> 
> If you choose to configure this integration for your personal, low-frequency local testing, **you do so entirely at your own risk**.

If you understand and accept these risks, the technical configuration in **Admin Panel > Settings > Web Search** is:

1. **Web Search Engine**: select `external`
2. **External Search URL**: `http://127.0.0.1:8765/search`
3. **External Search API Key**: your `API_KEY` value if configured, or any
   non-empty string if not

## systemd Deployment

```bash
sudo $EDITOR /etc/guiless-bing-search.conf
sudo systemctl enable --now guiless-bing-search
```

## Disclaimer

This project is provided **for personal study and research purposes only**. It is intended strictly for manual, interactive use via command-line interfaces (CLI) by individual users. It is not designed, authorized, or intended for automated scraping, bulk data extraction, or any high-frequency programmatic access. Any use of this tool for automated data collection or other purposes that violate the Terms of Service of the target search engine is strictly prohibited.

**For production deployment, automated workflows, or large-scale usage, please purchase and use Microsoft's official [Grounding with Bing](https://www.microsoft.com/en-us/bing/apis) service.** This tool is not a substitute for the official API and should not be used as such.

It is the user's sole responsibility to comply with all applicable laws and the terms of service of any third-party services accessed through this software. The author does **not** encourage or endorse any use that violates the [Microsoft Services Agreement](https://www.microsoft.com/servicesagreement).

By using this software you agree that **you bear all responsibility** for ensuring your usage complies with applicable terms of service and laws.

### Trademark Disclaimer

"Bing" is a registered trademark of Microsoft Corporation. This project is an independent, unofficial tool and is **not** affiliated with, authorized, maintained, sponsored, or endorsed by Microsoft Corporation or any of its affiliates.

## License

This project is licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later). See the [COPYING](COPYING) file for details.

This program is distributed in the hope that it will be useful, but **WITHOUT ANY WARRANTY**; without even the implied warranty of **MERCHANTABILITY** or **FITNESS FOR A PARTICULAR PURPOSE**. See the [GNU General Public License](https://www.gnu.org/licenses/gpl-3.0.html) for more details.
