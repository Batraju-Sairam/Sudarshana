# Sudarshana v5 - JavaScript Reconnaissance Toolkit

A powerful Python-based JavaScript reconnaissance tool designed for bug bounty hunters and security researchers to discover hidden paths, API endpoints, URLs, parameters, candidate secrets, source maps, interesting endpoints, and referenced JavaScript files.

![Sudarshana](assets/sudarshana-demo.gif)

## Features

* Scan JavaScript URLs from a text file
* Concurrent JavaScript scanning for faster reconnaissance
* Extract hidden API and application paths
* Discover absolute URLs inside JavaScript
* Extract parameter names from JavaScript
* Detect candidate API keys, tokens, credentials, and secrets
* Detect interesting paths such as admin, debug, staging, backup, GraphQL, Swagger, and configuration endpoints
* Detect JavaScript source maps
* Resolve source maps and extract original source files
* Automatically discover referenced JavaScript files
* Include/exclude domain scope filtering
* Aggressive mode for additional path discovery
* Silent mode for cleaner output
* Local JavaScript file scanning
* Save results into organized timestamped files
* Generate JSON reports
* Compare results against a previous baseline using diff mode
* Colored and categorized terminal output
* Live findings and scan statistics

---

## Prerequisites

* Python 3
* `curl`
* Linux / Kali Linux / macOS / WSL recommended

---

## Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/Batraju-Sairam/sudarshana.git
   cd sudarshana
   ```

2. **Make the script executable**

   ```bash
   chmod +x sudarshana.py
   ```

3. **Check the help menu**

   ```bash
   python3 sudarshana.py -h
   ```

---

## Input

Sudarshana uses a text file containing JavaScript URLs.

Example `js.txt`:

```text
https://example.com/static/js/app.js
https://example.com/static/js/main.js
https://example.com/assets/vendor.js
```

You can also use a local JavaScript file list with `--local`.

---

## Usage

```bash
python3 sudarshana.py [options]
```

### Options

| Option                 | Alias     | Description                                         |
| ---------------------- | --------- | --------------------------------------------------- |
| `--mode`               | `-m`      | Scan mode: `all`, `paths`, `urls`, `secrets`, `map` |
| `--input`              | `-i`      | Input JavaScript URL/file list                      |
| `--outdir`             | `-o`      | Directory to save results                           |
| `--scope`              | `-s`      | Include/exclude domains                             |
| `--timeout`            | `-t`      | HTTP request timeout                                |
| `--threads`            | `-c`      | Number of concurrent workers                        |
| `--delay`              |           | Delay between retries                               |
| `--retries`            |           | Number of HTTP retries                              |
| `--local`              |           | Scan local JavaScript files                         |
| `--aggressive`         |           | Enable aggressive/loose path discovery              |
| `--no-secrets`         |           | Disable secret detection                            |
| `--no-sourcemap`       |           | Disable source-map detection                        |
| `--resolve-sourcemaps` |           | Resolve downloadable source maps                    |
| `--json`               |           | Generate JSON report                                |
| `--diff`               |           | Compare against a previous result                   |
| `--no-follow`          |           | Disable JavaScript-to-JavaScript follow-up          |
| `--silent`             | `-silent` | Hide failed/empty targets                           |

---

## Scan Modes

### `all`

Scan for paths, URLs, parameters, candidate secrets, source maps, and interesting findings.

```bash
python3 sudarshana.py -i js.txt -m all
```

### `paths`

Extract paths from JavaScript.

```bash
python3 sudarshana.py -i js.txt -m paths
```

### `urls`

Extract absolute URLs.

```bash
python3 sudarshana.py -i js.txt -m urls
```

### `secrets`

Search for candidate secrets and tokens.

```bash
python3 sudarshana.py -i js.txt -m secrets
```

### `map`

Enable source-map related reconnaissance.

```bash
python3 sudarshana.py -i js.txt -m map
```

### Multiple modes

Modes can be combined using commas:

```bash
python3 sudarshana.py -i js.txt -m paths,urls
```

```bash
python3 sudarshana.py -i js.txt -m urls,secrets
```

---

## Examples

### Basic scan

```bash
python3 sudarshana.py -i js.txt
```

### Scan with scope

```bash
python3 sudarshana.py \
  -i js.txt \
  -s example.com
```

### Include multiple domains

```bash
python3 sudarshana.py \
  -i js.txt \
  -s 'example.com,api.example.com'
```

### Exclude a subdomain

```bash
python3 sudarshana.py \
  -i js.txt \
  -s 'example.com,!admin.example.com'
```

### Increase concurrency

```bash
python3 sudarshana.py \
  -i js.txt \
  -c 10
```

### Silent scanning

```bash
python3 sudarshana.py \
  -i js.txt \
  --silent
```

### Aggressive path discovery

```bash
python3 sudarshana.py \
  -i js.txt \
  --aggressive
```

### Save results

```bash
python3 sudarshana.py \
  -i js.txt \
  -o results/
```

### Generate JSON report

```bash
python3 sudarshana.py \
  -i js.txt \
  -o results/ \
  --json
```

### Resolve source maps

```bash
python3 sudarshana.py \
  -i js.txt \
  -o results/ \
  --resolve-sourcemaps
```

### Disable JavaScript follow-up

```bash
python3 sudarshana.py \
  -i js.txt \
  --no-follow
```

### Local JavaScript scanning

```bash
python3 sudarshana.py \
  -i local-js.txt \
  --local
```

### Compare with previous results

```bash
python3 sudarshana.py \
  -i js.txt \
  -o results/ \
  --diff previous.txt
```

---

## Scope Examples

Sudarshana supports both inclusion and exclusion rules.

### Only one target

```bash
-s example.com
```

### Multiple targets

```bash
-s 'example.com,api.example.com'
```

### Exclude a target

```bash
-s 'example.com,!admin.example.com'
```

This helps keep discovered URLs limited to the intended testing scope.

> Always verify the target against the official bug bounty program scope before testing.

---

## Detection

### Paths

Example:

```text
/api/users
/api/v1/accounts
/api/admin
/graphql
/swagger
/login
/reset-password
/upload
/internal/config
```

### URLs

Example:

```text
https://example.com/api/users
https://api.example.com/v1/login
https://example.com/graphql
```

### Parameters

Example:

```text
id
userId
accountId
token
redirect
callback
email
filename
url
```

### Candidate Secrets

Sudarshana can identify patterns associated with:

```text
AWS Access Keys
AWS Secret Keys
Google API Keys
Google OAuth Tokens
Firebase Server Keys
Slack Tokens
Slack Webhooks
Stripe Keys
GitHub Tokens
JWTs
Twilio Keys
Mailgun Keys
Mailchimp Keys
Square Tokens
Braintree/PayPal Tokens
Private Keys
Basic Authentication URLs
Generic API Keys
Generic Secrets
Bearer Tokens
```

> Secret detection is pattern-based. Findings must be manually verified before reporting or further testing.

### Interesting Findings

The tool highlights potentially interesting paths and URLs containing keywords such as:

```text
admin
internal
debug
staging
sandbox
backup
config
swagger
openapi
graphql
.env
.git
actuator
console
private
secret
dump
export
impersonation
sudo
superuser
reset
token
credential
upload
xxe
ssrf
```

---

## JavaScript Follow-Up

Sudarshana can discover JavaScript files referenced by other JavaScript files.

For example:

```text
app.js
   │
   ├── vendor.js
   ├── admin.js
   └── config.js
```

Newly discovered JavaScript URLs are saved as:

```text
new-js-urls-DD-MM-YYYY-HHMMSS.txt
```

Disable this behavior with:

```bash
python3 sudarshana.py \
  -i js.txt \
  --no-follow
```

---

## Source Maps

Sudarshana can detect `.map` references:

```text
app.js.map
main.js.map
bundle.js.map
```

To resolve downloadable source maps:

```bash
python3 sudarshana.py \
  -i js.txt \
  --resolve-sourcemaps \
  -o results/
```

---

## Output

When `-o` is specified, results are saved using timestamped filenames.

Example:

```text
results/
├── paths-DD-MM-YYYY-HHMMSS.txt
├── urls-DD-MM-YYYY-HHMMSS.txt
├── secrets-DD-MM-YYYY-HHMMSS.txt
├── params-DD-MM-YYYY-HHMMSS.txt
├── sourcemaps-DD-MM-YYYY-HHMMSS.txt
├── interesting-DD-MM-YYYY-HHMMSS.txt
├── errors-DD-MM-YYYY-HHMMSS.txt
├── new-js-urls-DD-MM-YYYY-HHMMSS.txt
└── results-DD-MM-YYYY-HHMMSS.json
```

Not every file is generated on every scan; files depend on the selected modes and options.

---

## Sample Output

```text
[*] Mode: all
[*] Scope: example.com
[*] Threads: 8

==> [OK] https://example.com/static/js/app.js

  URLS (3):
    https://example.com/api/login
    https://api.example.com/v1/users
    https://example.com/graphql

  PATHS (7):
    /api/login
    /api/users
    /graphql
    /admin
    /swagger
    /upload
    /reset-password

  PARAMS (5):
    accountId, callback, id, redirect, token

  SECRETS (1):
    AWS Access Key candidate

  SOURCEMAPS (1):
    https://example.com/static/js/app.js.map


========== COMPLETE ==========

JS files scanned : 100
Unique paths     : 84
Unique URLs      : 31
Candidate secrets: 1
Source maps      : 4
Param names      : 27
```

---

## Recommended Bug Bounty Workflow

```text
Subdomain Enumeration
        ↓
Live Host Discovery
        ↓
JavaScript Collection
        ↓
       js.txt
        ↓
   ┌─────────────┐
   │  Sudarshana │
   └─────────────┘
        ↓
 ┌──────┼───────┬──────────┐
 ↓      ↓       ↓          ↓
Paths  URLs   Params    Secrets
 ↓      ↓       ↓          ↓
 └──────┴───────┴──────────┘
             ↓
     Manual Validation
             ↓
       Burp Suite / ffuf
             ↓
      Security Testing
```

Sudarshana is intended to help with the **reconnaissance and attack-surface discovery stage**. It does not automatically confirm vulnerabilities such as XSS, IDOR, SQL injection, SSRF, or authentication bypass.

---

## Performance

Sudarshana uses concurrent workers to scan multiple JavaScript targets.

Default:

```text
Threads: 4
```

Example:

```bash
python3 sudarshana.py \
  -i js.txt \
  -c 10
```

For large target lists, choose a concurrency level appropriate for your machine, network, and the target's rate limits.

---

## Contributing

Feel free to submit issues or pull requests!

Suggestions for:

* New detection patterns
* Better JavaScript parsing
* New reconnaissance features
* Performance improvements
* Bug fixes
* Framework-specific detection

are welcome.

---

## License

[MIT](LICENSE) © [Batraju Sairam](https://github.com/Batraju-Sairam)

---

## Author

**Batraju Sairam**

GitHub: [Batraju-Sairam](https://github.com/Batraju-Sairam)

---

## ⚠️ Disclaimer

Sudarshana is intended for:

* Authorized penetration testing
* Bug bounty programs
* Security research
* CTF/lab environments
* Systems you own or have explicit permission to test

Do not use this tool against systems without authorization.

The author is not responsible for damage, disruption, or misuse resulting from unauthorized use of this tool.
