# Sudarshana v5

**Sudarshana** is a concurrent JavaScript reconnaissance tool designed for **bug bounty hunters, web penetration testers, and security researchers**.

It analyzes JavaScript files to discover:

* 🔗 URLs
* 📁 API paths and endpoints
* 🔐 Candidate secrets and credentials
* 🧩 Parameter names
* 🗺️ Source maps
* 🔎 Interesting/high-value endpoints
* 🔄 JavaScript files referenced by other JavaScript files
* 📊 Source-to-path / source-to-URL mappings
* 📈 Changes between reconnaissance runs

Sudarshana is designed to fit naturally into a modern bug bounty workflow such as:

```text
Subdomain Enumeration
        ↓
HTTP Probing
        ↓
JavaScript URL Collection
        ↓
            Sudarshana
        ↓
 ┌──────────┼──────────┐
 ↓          ↓          ↓
Paths      URLs     Secrets
 ↓          ↓          ↓
Parameters  APIs    Manual Verification
        ↓
Further Recon / Testing
```

> **Important:** Sudarshana identifies potentially interesting artifacts. It does **not** automatically prove that a vulnerability or exposed credential is exploitable. Always manually verify findings and follow the target's authorization and bug bounty policy.

---

## ✨ Features

### 🔗 URL Extraction

Extracts absolute URLs referenced inside JavaScript:

```text
https://api.example.com/users
https://api.example.com/v1/account
https://cdn.example.com/config
```

Protocol-relative URLs are also normalized:

```text
//api.example.com/v1/users
```

becomes:

```text
https://api.example.com/v1/users
```

---

### 📁 API Path Discovery

Detects quoted paths such as:

```javascript
fetch("/api/users");
fetch("/api/v1/profile");
axios.get("/admin/settings");
```

Example output:

```text
PATHS (3):
    /api/users
    /api/v1/profile
    /admin/settings [interesting]
```

---

### 🔎 Aggressive Path Discovery

Use:

```bash
--aggressive
```

to detect less strictly delimited paths.

Example:

```javascript
const endpoint = /api/v2/users/profile;
```

Because aggressive extraction is intentionally broader, it can produce more false positives.

```text
PATHS — loose/unverified:
    /api/v2/users/profile
```

---

### 🔐 Secret Detection

Sudarshana contains built-in patterns for common credential/token formats.

Currently detected categories include:

| Category                    | Confidence |
| --------------------------- | ---------- |
| AWS Access Key ID           | High       |
| AWS Secret Access Key       | Medium     |
| Google API Key              | High       |
| Google OAuth Token          | High       |
| Firebase Server Key         | High       |
| Slack Token                 | High       |
| Slack Webhook               | High       |
| Stripe Live Secret Key      | High       |
| Stripe Live Publishable Key | High       |
| GitHub Token                | High       |
| GitHub Fine-grained PAT     | High       |
| JWT                         | High       |
| Twilio API Key SID          | Medium     |
| Twilio Account SID          | Medium     |
| Mailgun API Key             | Medium     |
| Mailchimp API Key           | High       |
| Square Access Token         | High       |
| Braintree/PayPal Token      | High       |
| Private Key Block           | High       |
| Basic Auth in URL           | High       |
| Generic API Key             | Low        |
| Generic Secret Assignment   | Low        |
| Hardcoded Bearer Token      | Low        |

Example:

```text
SECRETS (2) — candidates only, verify before reporting:

    [HIGH] Google API Key: AIza...
    [LOW] Generic API Key Assign: apiKey="..."
```

### ⚠️ Important

Secret detection is **pattern-based**.

A match does **not** automatically mean:

* the credential is valid
* the credential is active
* the credential belongs to the target
* the credential provides unauthorized access
* the finding is bounty-eligible

Always perform authorized validation before reporting.

---

## 🗺️ Source Map Discovery

Sudarshana detects JavaScript source map references such as:

```javascript
//# sourceMappingURL=app.js.map
```

Run:

```bash
-m map
```

or:

```bash
--resolve-sourcemaps
```

to investigate source maps.

When source-map resolution is enabled, JSRecon can retrieve discovered `.map` files and extract their original source paths.

Example:

```text
SOURCEMAPS:
    https://example.com/static/app.js.map
```

Resolved sources may reveal paths such as:

```text
src/api/auth.js
src/components/AdminPanel.jsx
src/config/environment.js
```

These are useful for further manual reconnaissance.

---

## 🧩 Parameter Discovery

JSRecon attempts to identify parameter names from:

### Query strings

```text
/api/user?id=123
```

→

```text
id
```

### Object literals

```javascript
fetch("/api/login", {
    body: {
        username: user,
        password: pass
    }
});
```

→

```text
username
password
```

### Property access

```javascript
params.userId
query.accountId
body.email
```

→

```text
userId
accountId
email
```

### `URLSearchParams`

```javascript
params.get("redirect")
```

→

```text
redirect
```

### FormData

```javascript
formData.append("file", upload)
```

→

```text
file
```

These parameter names can help build a more focused testing list for authorized targets.

---

# 🎯 Interesting Endpoint Detection

JSRecon highlights paths and URLs matching potentially interesting keywords.

Examples include:

```text
/admin
/internal
/debug
/staging
/swagger
/openapi
/graphql
/.git
/.env
/actuator
/console
/private
/secret
/export
/upload
/token
/credential
/reset-password
/forgot-password
/api/v1/users
/api/v1/admin
```

Example:

```text
/api/v1/admin/users [interesting]
/internal/debug/config [interesting]
/swagger/index.html [interesting]
```

> Interesting does not mean vulnerable. It simply means the artifact deserves additional investigation.

---

# 🔄 JavaScript Follow-Up

JSRecon automatically follows **one level** of JavaScript references discovered inside scanned JavaScript files.

For example:

```text
js.txt
│
├── https://example.com/js/main.js
│
└── main.js references
        ↓
    /js/admin.js
        ↓
    JSRecon scans admin.js
```

Output:

```text
[*] Following 4 newly discovered JS link(s)...
```

The discovered files are saved as:

```text
new-js-urls-DD-MM-YYYY-HHMMSS.txt
```

Disable this behavior with:

```bash
--no-follow
```

---

# 🎯 Scope Filtering

You can restrict discovered URLs to authorized domains.

Single domain:

```bash
-s example.com
```

Multiple domains:

```bash
-s "example.com,api.example.com"
```

Exclude a domain:

```bash
-s "example.com,!admin.example.com"
```

Example:

```bash
python3 jsrecon.py \
    -i js.txt \
    -s "example.com,!admin.example.com"
```

Scope matching supports subdomains.

For example:

```text
example.com
```

also permits:

```text
api.example.com
dev.example.com
cdn.example.com
```

while:

```text
!admin.example.com
```

excludes:

```text
admin.example.com
```

---

# ⚡ Concurrent Scanning

JSRecon uses multiple workers for concurrent fetching.

Default:

```text
4 threads
```

Change it with:

```bash
-c 10
```

Example:

```bash
python3 jsrecon.py -i js.txt -c 10
```

Higher thread counts can increase speed but may also increase traffic against the target.

Use reasonable values according to the program's rate limits.

---

# 🔁 Retry Support

Default:

```text
Retries: 2
```

Change it:

```bash
--retries 5
```

Optional retry delay:

```bash
--delay 1
```

Example:

```bash
python3 jsrecon.py \
    -i js.txt \
    -c 8 \
    --retries 3 \
    --delay 1
```

---

# 🤫 Silent Mode

By default, JSRecon prints every scanned target.

Use:

```bash
--silent
```

to hide failed/empty targets and show only targets that produce findings.

Both forms are supported:

```bash
--silent
```

and:

```bash
-silent
```

Output remains in the same order as the input file.

---

# 💾 Output

JSRecon does **not write anything to disk by default**.

This means:

```bash
python3 jsrecon.py -i js.txt
```

only displays results in the terminal.

To save results:

```bash
-o results
```

Example:

```bash
python3 jsrecon.py \
    -i js.txt \
    -o results
```

Files use a shared timestamp:

```text
results/
├── paths-15-09-2026-074500.txt
├── urls-15-09-2026-074500.txt
├── secrets-15-09-2026-074500.txt
├── params-15-09-2026-074500.txt
├── sourcemaps-15-09-2026-074500.txt
├── interesting-15-09-2026-074500.txt
├── new-js-urls-15-09-2026-074500.txt
└── errors-15-09-2026-074500.txt
```

Only relevant files are created depending on the selected mode and options.

---

# 📋 Input Format

By default:

```text
js.txt
```

contains one JavaScript URL per line.

Example:

```text
https://example.com/static/app.js
https://example.com/assets/main.js
https://cdn.example.com/js/vendor.js
```

Comments are supported:

```text
# Production JavaScript
https://example.com/js/app.js

# CDN
https://cdn.example.com/js/main.js
```

Duplicate entries are automatically removed.

---

# 🖥️ Local File Mode

JSRecon can also analyze local JavaScript files.

Use:

```bash
--local
```

Example:

```bash
python3 jsrecon.py \
    --local \
    -i local-js.txt
```

`local-js.txt`:

```text
./javascript/app.js
./javascript/main.js
./downloads/vendor.js
```

In local mode, JS URL follow-up is disabled because there are no live URLs to fetch.

---

# 🎛️ Scan Modes

JSRecon supports:

```text
all
paths
urls
secrets
map
```

Multiple modes can be combined.

---

## All

Default:

```bash
python3 jsrecon.py -i js.txt
```

Equivalent to:

```bash
-m all
```

---

## Paths Only

```bash
python3 jsrecon.py \
    -i js.txt \
    -m paths
```

---

## URLs Only

```bash
python3 jsrecon.py \
    -i js.txt \
    -m urls
```

---

## Secrets Only

```bash
python3 jsrecon.py \
    -i js.txt \
    -m secrets
```

---

## Map Mode

```bash
python3 jsrecon.py \
    -i js.txt \
    -m map
```

Map mode enables source/path mapping while also displaying the main discovery categories.

---

## Multiple Modes

Example:

```bash
python3 jsrecon.py \
    -i js.txt \
    -m urls,secrets
```

Another example:

```bash
python3 jsrecon.py \
    -i js.txt \
    -m paths,urls
```

---

# 📊 Mapping Mode

When mapping is enabled, output files contain the relationship between the discovered artifact and the JavaScript file that referenced it.

Example:

```text
/api/v1/users    https://example.com/js/app.js
/api/v1/admin    https://example.com/js/admin.js
```

This is useful when you have hundreds or thousands of JavaScript files and need to determine:

> "Which JS file revealed this endpoint?"

---

# 📈 Diff Mode

Compare the current run against a previous baseline.

Example:

```bash
python3 jsrecon.py \
    -i js.txt \
    -o results \
    --diff baseline.txt
```

The tool identifies newly discovered paths and URLs that were not present in the baseline.

Output:

```text
new-findings-DD-MM-YYYY-HHMMSS.txt
```

This can be useful for:

* Continuous recon
* Monitoring endpoint changes
* Tracking newly deployed functionality
* Comparing production releases
* Bug bounty target monitoring

---

# 🧾 JSON Output

Use:

```bash
--json
```

Example:

```bash
python3 jsrecon.py \
    -i js.txt \
    -o results \
    --json
```

The resulting JSON contains structured information such as:

```json
{
  "scanned": 100,
  "elapsed_seconds": 12.4,
  "paths": [],
  "urls": [],
  "loose_paths": [],
  "interesting": [],
  "params": [],
  "secrets": [],
  "sourcemaps": [],
  "sourcemap_sources": {},
  "discovered_js": [],
  "errors": []
}
```

This makes the output easier to integrate into other automation pipelines.

---

# 🚀 Installation

## Requirements

JSRecon requires:

* Python 3.8+
* `curl`

Check Python:

```bash
python3 --version
```

Check curl:

```bash
curl --version
```

No third-party Python packages are required.

---

# 📦 Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/JSRecon.git
cd JSRecon
```

Make the script executable:

```bash
chmod +x jsrecon.py
```

Run:

```bash
./jsrecon.py -i js.txt
```

Or:

```bash
python3 jsrecon.py -i js.txt
```

---

# 🔥 Bug Bounty Workflow

A practical workflow can look like this:

### 1. Collect JavaScript URLs

For example, using your preferred authorized reconnaissance tools:

```bash
subfinder -d example.com -all -recursive
```

Then collect URLs using tools such as:

```text
httpx
gau
waybackurls
katana
```

Create:

```text
js.txt
```

containing JavaScript URLs.

---

### 2. Run JSRecon

```bash
python3 jsrecon.py \
    -i js.txt \
    -s example.com \
    -o jsrecon-results
```

---

### 3. Focus on interesting endpoints

Review:

```text
interesting-*.txt
paths-*.txt
urls-*.txt
```

Look for functionality such as:

```text
/admin
/internal
/debug
/staging
/swagger
/graphql
/upload
/export
/reset-password
/api/v1/users
```

---

### 4. Investigate Parameters

Review:

```text
params-*.txt
```

Potential parameters might include:

```text
id
userId
accountId
redirect
returnUrl
file
url
callback
role
```

These can help guide further authorized testing.

---

### 5. Verify Candidate Secrets

Review:

```text
secrets-*.txt
```

Do **not** assume a match is a vulnerability.

Determine whether:

```text
1. The value is real
2. It is active
3. It belongs to the target
4. It provides meaningful access
5. The access is authorized to test
6. The exposure violates the program policy
```

---

# 🧪 Example Commands

### Basic

```bash
python3 jsrecon.py
```

### Custom input

```bash
python3 jsrecon.py -i javascript.txt
```

### Save results

```bash
python3 jsrecon.py \
    -i js.txt \
    -o results
```

### URLs + secrets

```bash
python3 jsrecon.py \
    -i js.txt \
    -m urls,secrets
```

### Paths only

```bash
python3 jsrecon.py \
    -i js.txt \
    -m paths
```

### Aggressive path discovery

```bash
python3 jsrecon.py \
    -i js.txt \
    --aggressive
```

### Scope restricted

```bash
python3 jsrecon.py \
    -i js.txt \
    -s example.com
```

### Scope with exclusions

```bash
python3 jsrecon.py \
    -i js.txt \
    -s "example.com,!admin.example.com"
```

### Faster scanning

```bash
python3 jsrecon.py \
    -i js.txt \
    -c 10
```

### Silent output

```bash
python3 jsrecon.py \
    -i js.txt \
    --silent
```

### Source-map resolution

```bash
python3 jsrecon.py \
    -i js.txt \
    --resolve-sourcemaps
```

### JSON output

```bash
python3 jsrecon.py \
    -i js.txt \
    -o results \
    --json
```

### Disable JS follow-up

```bash
python3 jsrecon.py \
    -i js.txt \
    --no-follow
```

### Local JavaScript analysis

```bash
python3 jsrecon.py \
    --local \
    -i local-js.txt
```

---

# 🛠️ Command-Line Options

```text
-m, --mode
    Scan mode:
    all, paths, urls, secrets, map

-i, --input
    Input file containing JS URLs or local paths.

-o, --outdir
    Directory where results should be saved.

-s, --scope
    Authorized scope/domain filtering.

-t, --timeout
    HTTP request timeout.
    Default: 20 seconds.

-c, --threads
    Concurrent fetch workers.
    Default: 4.

--delay
    Base delay before retries.
    Default: 0.

--retries
    Number of retries.
    Default: 2.

--local
    Treat input entries as local files.

--aggressive
    Enable loose/unquoted path extraction.

--no-secrets
    Disable secret scanning.

--no-sourcemap
    Disable source-map detection.

--resolve-sourcemaps
    Fetch discovered source maps and extract source paths.

--json
    Write structured JSON results.
    Requires --outdir.

--diff BASELINE
    Compare findings against a previous baseline.

--no-follow
    Disable one-level JavaScript follow-up.

--silent
    Hide failed/empty targets from live output.
```

---

# 🧠 How JSRecon Works

At a high level:

```text
Input JS URLs
      │
      ▼
Deduplicate
      │
      ▼
Extension Filtering
      │
      ├── Skip: css/png/svg/jpg/gif/etc.
      │
      ▼
Concurrent Fetch
      │
      ▼
HTML / Soft-200 Filtering
      │
      ▼
JavaScript Analysis
      │
      ├── URL Extraction
      ├── Path Extraction
      ├── Secret Detection
      ├── Parameter Extraction
      ├── Source-map Detection
      └── Interesting Endpoint Detection
      │
      ▼
JS → JS Discovery
      │
      ▼
One-Level Follow-Up
      │
      ▼
Deduplication + Aggregation
      │
      ▼
Console / TXT / JSON Output
```

---

# 🚫 Static Asset Filtering

JSRecon automatically skips files with these extensions:

```text
woff
css
png
svg
jpg
woff2
jpeg
gif
```

This helps avoid wasting requests and scanning obvious non-JavaScript resources.

---

# 🔐 Security & Responsible Use

JSRecon is intended for:

* Authorized penetration testing
* Bug bounty programs
* Security research
* Assets you own
* Lab environments
* CTFs

Only scan systems where you have permission to do so.

Do not use JSRecon to:

* Access unauthorized systems
* Exploit discovered credentials without authorization
* Perform destructive testing
* Bypass security controls outside program rules
* Exfiltrate sensitive information
* Attack third-party infrastructure

Always follow the target's:

* Scope
* Rate limits
* Testing restrictions
* Disclosure policy
* Safe-harbor requirements

---

# ⚠️ False Positives

Regex-based reconnaissance naturally produces false positives.

Examples:

```text
Generic API Key
Generic Secret
Bearer Token
JWT
Google API Key
AWS-related strings
```

A discovered string may be:

* Dummy data
* Test credentials
* Expired credentials
* Public client-side configuration
* Documentation examples
* A non-sensitive identifier
* A false regex match

**Always manually verify before reporting.**

---

# 📌 Limitations

JSRecon is intentionally lightweight and regex-based.

It does not currently perform:

* Full JavaScript AST analysis
* Browser execution
* DOM-based taint analysis
* Automatic authentication
* Automatic vulnerability exploitation
* Credential validation
* API fuzzing
* JavaScript deobfuscation beyond basic Unicode/hex decoding
* Multi-level recursive JS crawling
* Headless browser rendering

Its primary purpose is **fast JavaScript reconnaissance and attack-surface discovery**.

---

# 🔮 Future Roadmap

Potential future improvements:

* [ ] JavaScript AST parsing
* [ ] Better minified JS analysis
* [ ] Enhanced secret validation
* [ ] More cloud credential patterns
* [ ] Nuclei integration
* [ ] HTTP probing integration
* [ ] Automatic endpoint normalization
* [ ] Parameter classification
* [ ] Endpoint risk scoring
* [ ] Better source-map analysis
* [ ] Multi-level JS dependency crawling
* [ ] Authentication-aware scanning
* [ ] Burp Suite integration
* [ ] SQLite/JSON database output
* [ ] HTML reporting
* [ ] Configurable regex/signature files
* [ ] API schema extraction
* [ ] OpenAPI/Swagger discovery integration

---

# 🤝 Contributing

Contributions, improvements, new detection patterns, bug fixes, and feature ideas are welcome.

Before submitting a pull request:

1. Test the change against representative JavaScript.
2. Avoid introducing unnecessary dependencies.
3. Keep false positives in mind.
4. Document new command-line options.
5. Do not add functionality intended for unauthorized exploitation.

---

# 📄 License

Choose a license for your repository before publishing.

For example:

```text
MIT License
```

If using MIT, add a `LICENSE` file containing the official MIT License text.

---

# ⭐ Author

**JSRecon** was created as a practical JavaScript reconnaissance utility for security researchers and bug bounty workflows.

If you find it useful, consider ⭐ starring the repository and contributing improvements.

---

## ⚡ Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/JSRecon.git
cd JSRecon

chmod +x jsrecon.py

python3 jsrecon.py \
    -i js.txt \
    -s example.com \
    -o results
```

Then review:

```text
results/
├── paths-*.txt
├── urls-*.txt
├── secrets-*.txt
├── params-*.txt
├── sourcemaps-*.txt
├── interesting-*.txt
└── new-js-urls-*.txt
```

**Find → Prioritize → Verify → Report responsibly.**
