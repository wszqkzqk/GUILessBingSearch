# GUI-Less Bing Search

An unofficial tool for accessing Bing search results in environments **without a graphical user interface**, built for personal study and research on headless information retrieval.

In many server, container, or embedded environments there is no desktop or browser available, yet users still need to look up information on the web. This tool wraps Qt6 WebEngine (PySide6) as a headless Chromium engine and exposes a minimal HTTP API so that users can query Bing via `curl` or similar command-line utilities.

Because no result links are fed back to Bing, the tool does not leak which results the user actually visited, offering a degree of privacy protection compared to using a regular browser.

**Disclaimer:** This tool is an independent, unofficial project created for educational purposes, personal accessibility, and academic research on headless information retrieval. It acts as a local browser wrapper to facilitate personal workflows and interoperability. It is not intended for bulk scraping, commercial use, or bypassing of any official APIs. Users are encouraged to respect fair use principles and the terms of service of the websites they access.

## Dependencies

- `python>=3.10.0`
- `pyside6`
- `qt6-webengine`

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
| `BING_ENSEARCH` | (auto) | `1` = force international, `0` = force domestic on cn.bing.com, unset = adaptive: add `ensearch=1` only when the base URL host is `cn.bing.com` |
| `BING_BASE_URL` | `https://www.bing.com` | Base URL for Bing search. Outside mainland China, keep the default. If your network redirects `www.bing.com` to `cn.bing.com`, set this explicitly to `https://cn.bing.com` |
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

In certain network environments (notably mainland China), accessing `www.bing.com` may redirect to `cn.bing.com` or involve cookie-dependent routing, which can leave the browser profile in a broken state and cause searches to fail or return incorrect results.

If you experience this problem, try one of the following:

1. **Delete the profile directory** to start with a clean state.
2. **Set `BING_BASE_URL=https://cn.bing.com`** if your network reliably lands on the mainland endpoint and you want deterministic behavior.
3. **Set `BING_U_COOKIE`** or `BING_EXTRA_COOKIES` to supply known-good cookie values that resolve the redirect issue.

If your network can reach `bing.com` without issues, you do not need to
set any cookie variables.

By default, the program behaves as follows:

1. If the base URL host is `www.bing.com`, it uses the normal international search flow and does not append `ensearch`.
2. If the base URL host is `cn.bing.com`, it appends `ensearch=1` by default to stay on the international results path.
3. If you set `BING_ENSEARCH=0`, it forces the domestic cn.bing.com mode.

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

## OpenWebUI Integration

While this tool is primarily designed for CLI usage, its standard HTTP JSON interface allows for local interoperability with other tools, such as [OpenWebUI](https://github.com/open-webui/open-webui).

> **Note on Interoperability**
> 
> Connecting this tool to local frontends is provided as an example of personal workflow enhancement. This setup is intended for low-frequency, local debugging and study purposes. It is not a replacement for commercial search APIs, and users should ensure their usage respects fair use guidelines.

If you choose to configure this integration, the technical configuration in **Admin Panel > Settings > Web Search** is:

1. **Web Search Engine**: select `external`
2. **External Search URL**: `http://127.0.0.1:8765/search`
3. **External Search API Key**: your `API_KEY` value if configured, or any
   non-empty string if not

## MCP integration

> **Note on MCP Integration**
>
> The built-in MCP (Model Context Protocol) endpoint demonstrates local interoperability between headless browsers and AI agents for personal, low-frequency workflows. This integration allows individuals to streamline their daily research tasks in a privacy-respecting manner.
>
> It is provided strictly as an educational example of local agent integration. For any commercial or production-grade automated search workflows, please use the official [Grounding with Bing Search API](https://www.microsoft.com/en-us/bing/apis).

The built-in MCP endpoint (`/mcp`) reuses the same running server process.
No extra wrapper process is required.
MCP uses the same Bearer authentication as `/search`.

Available MCP tool:
- `search_bing` with input `{ "query": "...", "count": 5 }`
- Returns rendered Markdown text with search results

Claude Code example:

```bash
# no auth
claude mcp add --transport http bing-search http://127.0.0.1:8765/mcp

# if server uses --api-key
claude mcp add --transport http bing-search http://127.0.0.1:8765/mcp \
  --header "Authorization: Bearer mysecretkey"
```

Optional Claude Code config:

These files are user-managed and are not auto-created by package installation.

- **Project-scoped**: create `.mcp.json` in your project root.
- **User-scoped (global)**: configure `~/.claude.json` under `mcpServers`, or run:
  ```bash
  claude mcp add --transport http --scope user bing-search http://127.0.0.1:8765/mcp
  ```

Example `.mcp.json` (project-scoped):

```json
{
  "mcpServers": {
    "bing-search": {
      "type": "http",
      "url": "${BING_SEARCH_MCP_URL:-http://127.0.0.1:8765/mcp}",
      "headers": {
        "Authorization": "Bearer ${BING_SEARCH_API_KEY:-}"
      }
    }
  }
}
```

OpenCode config (`opencode.json` in project root, or `~/.config/opencode/opencode.json` for global user config):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "bing_search": {
      "type": "remote",
      "url": "http://127.0.0.1:8765/mcp",
      "enabled": true,
      "oauth": false,
      "headers": {
        "Authorization": "Bearer {env:BING_SEARCH_API_KEY}"
      }
    }
  }
}
```

Hardcoded values are also valid in both configs, for example: `"Authorization": "Bearer mysecretkey"`.

When auth is disabled, the `Authorization` header can be omitted.

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
