# JS Extractor & Beautifier v2

A command-line tool that extracts **all JavaScript** from any web page, beautifies it into human-readable code, and then analyzes it for API endpoints, hidden routes, fuzzing parameters, leaked secrets, and more.

Supports cookie-based auth, JWT tokens, and arbitrary custom headers — making it practical for authenticated SPAs and web applications.

---

## Features

### Extraction
| Feature | Description |
|---|---|
| Static extraction | Parses initial HTML for `<script src>` and inline `<script>` tags |
| **Dynamic extraction** `--dynamic` | Launches headless Chromium (Playwright) to capture lazy-loaded and async scripts |
| **Import chain following** | Recursively fetches JS files referenced via `import`/`require` inside scripts |
| **Source map recovery** | Detects `.js.map` references and extracts original pre-bundle source files |
| **Web Worker / Service Worker** | Finds and downloads worker scripts registered in the JS code |

### Analysis
| Feature | Flag | Description |
|---|---|---|
| Framework detection | *(always on)* | Identifies React, Next.js, Vue, Nuxt, Angular, Svelte, Webpack, Vite, GraphQL, and more |
| **Endpoint extraction** | `--endpoints` | Finds all API routes in JS; flags hidden/internal ones separately |
| **Parameter extraction** | `--params` | Collects parameter names from query strings, request bodies, route params, and form fields — saves a ready-to-use fuzzing wordlist |
| **Secret detection** | `--secrets` | Scans for leaked API keys, JWTs, AWS/GitHub/Slack tokens, passwords, private key blocks |
| **HTML report** | `--report` | Generates a self-contained report with all findings |

---

## Installation

**Requirements:** Python 3.10+

```bash
pip install requests beautifulsoup4 jsbeautifier playwright sourcemap

# Only needed if you use --dynamic:
playwright install chromium
```

---

## Usage

```bash
python3 js_extractor.py <url> [options]
```

### Full Options

```
Authentication:
  --cookie "name=value; name2=value2"   Cookie string
  --jwt    "eyJ..."                      JWT token (Bearer prefix optional)
  --header "Key: Value"                  Custom header (repeatable)

Extraction:
  --dynamic           Use headless Chromium (captures lazy-loaded scripts)
  --no-inline         Skip inline <script> blocks
  --no-external       Skip external .js files
  --no-workers        Skip Web Worker / Service Worker scripts
  --no-sourcemaps     Skip source map recovery
  --no-imports        Skip following import/require chains

Analysis:
  --endpoints         Extract API endpoints + flag hidden/internal routes
  --params            Extract parameters; save fuzzing wordlist
  --secrets           Scan for leaked keys, tokens, passwords
  --all-analysis      Enable all three analysis flags above

Output:
  --output-dir DIR    Output directory (default: ./js_output)
  --merge             Combine all scripts into ALL_SCRIPTS_MERGED.js
  --report            Generate HTML report
```

---

## Examples

**Basic — no auth:**
```bash
python3 js_extractor.py https://example.com
```

**With cookie auth + full analysis:**
```bash
python3 js_extractor.py https://app.example.com \
  --cookie "session=abc123; csrf=xyz" \
  --all-analysis \
  --report
```

**With JWT + dynamic JS capture:**
```bash
python3 js_extractor.py https://app.example.com \
  --jwt "eyJhbGciOiJIUzI1NiJ9..." \
  --dynamic \
  --endpoints \
  --params
```

**Full recon — everything enabled:**
```bash
python3 js_extractor.py https://app.example.com \
  --jwt "Bearer eyJ..." \
  --cookie "csrftoken=abc" \
  --dynamic \
  --all-analysis \
  --merge \
  --report \
  --output-dir ./recon_output
```

---

## Output Structure

```
js_output/
├── external/
│   ├── ext_001_a3f9c1_main.js          # beautified external scripts
│   ├── ext_002_b7e421_vendor.chunk.js  # followed import chunk
│   └── ...
├── inline/
│   ├── inline_001.js                   # beautified inline <script> blocks
│   └── ...
├── sourcemap_recovered/
│   ├── src/components/App.jsx          # original source files from .map
│   └── ...
├── endpoints.txt                       # all discovered API endpoints
├── endpoints_hidden.txt                # internal/admin/hidden routes only
├── params_wordlist.txt                 # parameter names for fuzzing
├── ALL_SCRIPTS_MERGED.js              # (--merge) single combined file
└── report.html                        # (--report) full HTML report
```

---

## Endpoint Detection

The `--endpoints` flag scans all JS for:
- `fetch(...)` and `axios.get/post/put/patch/delete(...)` calls
- URL/path/endpoint variable assignments
- String literals matching `/api/`, `/v1/`, `/graphql/`, `/auth/`, etc.
- Template literals with path prefixes

**Hidden endpoint detection** automatically flags any route containing words like `admin`, `internal`, `debug`, `secret`, `private`, `panel`, `console`, `backdoor`.

```
[+] Found 34 endpoint(s)  (3 flagged as hidden/internal)
    [!] Hidden/Internal endpoints:
        /admin/hidden-panel
        /internal/debug
        /api/v1/admin/users
```

---

## Parameter Extraction & Fuzzing

The `--params` flag extracts parameter names from:
- Query string keys: `?user_id=&limit=&offset=`
- Request body object keys: `{ email, password, remember_me }`
- `URLSearchParams` / `FormData` `.append()` / `.set()` calls
- Express-style route params: `/users/:userId/orders/:orderId`
- HTML `<input name="...">` fields in JS templates

Saves a clean **`params_wordlist.txt`** ready to use directly with tools like `ffuf`, `wfuzz`, or `Burp Suite`:

```bash
ffuf -u https://target.com/api/FUZZ -w js_output/params_wordlist.txt
```

---

## Secret Detection

Patterns covered by `--secrets`:

| Pattern | Examples |
|---|---|
| Generic API keys | `api_key = "abc123..."` |
| OpenAI keys | `sk-...`, `sk-proj-...` |
| Google API keys | `AIza...` |
| AWS Access keys | `AKIA...` |
| GitHub tokens | `ghp_...`, `gho_...` |
| GitLab tokens | `glpat-...` |
| Slack tokens | `xoxb-...`, `xoxp-...` |
| Facebook tokens | `EAA...` |
| JWT tokens | `eyJ...` |
| Private key blocks | `-----BEGIN RSA PRIVATE KEY-----` |
| Hex secrets | 32+ hex chars after `secret`/`token`/`key` |

Values are **masked** in terminal output and the HTML report. Full values appear only in raw JS files.

---

## How It Works

```
1. Fetch the target page (static or via headless browser)
2. Parse HTML → collect <script src> URLs and inline blocks
3. Download each external JS file
4. For each JS file:
   a. Beautify (indent, unescape strings, fix spacing)
   b. Check for sourceMappingURL → fetch & extract original sources
   c. Find import/require references → add to download queue
   d. Find new Worker() / serviceWorker.register() → add to queue
5. Run analysis on all collected JS:
   - Detect frameworks
   - Extract endpoints + flag hidden ones
   - Extract params → save wordlist
   - Scan for secrets
6. Generate HTML report (optional)
```

---

## Limitations

- **Dynamic scripts only with `--dynamic`**: scripts injected by JS after page load are not captured in static mode.
- **Source map recovery**: requires `sourcesContent` to be embedded in the `.map` file. External source servers are not fetched.
- **Obfuscation**: `js-beautifier` fixes formatting but does not deobfuscate intentionally obfuscated code (e.g. `eval`-packed, hex-encoded logic).
- **Scope**: only analyzes the initial target URL. Use `--dynamic` to catch lazy-loaded chunks.

---

## License

MIT
