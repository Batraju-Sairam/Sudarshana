#!/usr/bin/env python3
"""
Sudarshana — concurrent JS reconnaissance for bug bounty workflows.

- Modes (-m): all, paths, urls, secrets, map — comma-separated, e.g. -m urls,secrets
- Live output prints strictly in js.txt order, filtered to the chosen mode(s)
- --silent hides failed/empty targets from the live feed; real hits still show
- Nothing is written to disk unless -o is given; with -o, every file gets a
  <category>-<DD-MM-YYYY>-<HHMMSS>.txt name from one shared run timestamp
- Follows one level of JS-referencing-JS links discovered inside scanned files
  (respecting --scope if given), and records them in new-js-urls-<ts>.txt
"""
import argparse, concurrent.futures as cf, html, json, random, re, subprocess
import sys, threading, time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, urljoin

C="\033[1;36m"; G="\033[1;32m"; Y="\033[1;33m"; B="\033[1;34m"
M="\033[1;35m"; W="\033[1;37m"; R="\033[1;31m"; D="\033[2;90m"; O="\033[1;91m"; X="\033[0m"

# ───────────────────────── startup banner ─────────────────────────

_CHAKRA = r"""
                                  ***********
                             ****   |||   ****
                          ***\      |      /***
                         **  \\\    |    ///  **
                       **      \   |   /      **
                       **        \ | /        **
                       **---------OOO---------**
                       **        / | \        **
                       **      /   |   \      **
                         **  ///    |    \\\  **
                          ***/      |      \***
                             ****   |||   ****
                                  ***********
""".strip("\n")

_TITLE = r"""
   ████  █   █  ████    ███   ████    ████  █   █   ███   █   █   ███
  █      █   █  █   █  █   █  █   █  █      █   █  █   █  ██  █  █   █
   ███   █   █  █   █  █████  ████    ███   █████  █████  █ █ █  █████
      █  █   █  █   █  █   █  █  █       █  █   █  █   █  █  ██  █   █
  ████    ███   ████   █   █  █   █  ████   █   █  █   █  █   █  █   █
""".strip("\n")

def print_banner():
    width = 72
    print(f"{C}{'='*width}{X}")
    for line in _CHAKRA.splitlines():
        print(f"{Y}{line.center(width)}{X}")
    print()
    for line in _TITLE.splitlines():
        print(f"{M}{line.center(width)}{X}")
    print(f"{D}{'JS Recon * Bug Bounty Toolkit'.center(width)}{X}")
    print(f"{C}{'='*width}{X}\n")

# ───────────────────────── regexes ─────────────────────────

URL_RE = re.compile(
    r'''(?:https?:)?//[A-Za-z0-9](?:[A-Za-z0-9\-._~:/?#@!$&*+,;=%]|%[0-9A-Fa-f]{2})*''', re.I)

PATH_RE  = re.compile(r'''(?:"|'|`)(/[^/"'\s`<>()][^"'\s`<>()]*)(?:"|'|`)''')
BAD_PATH = re.compile(r'^/(?:\*\\?\?|\\\?|\*|\.\.?/)', re.I)

LOOSE_PATH_RE = re.compile(
    r'''(?<![:/.\w])/(?!/)[A-Za-z][A-Za-z0-9_\-./%]{1,200}(?=[\s"'`<>,;)\]}]|$)''')
REGEX_LITERAL_CTX = re.compile(r'\.(?:replace|match|test|exec|search)\(\s*$')

UNI_ESC = re.compile(r'\\u([0-9a-fA-F]{4})')
HEX_ESC = re.compile(r'\\x([0-9a-fA-F]{2})')

SOURCEMAP_RE = re.compile(r'//[#@]\s*sourceMappingURL=([^\s*]+)')

QPARAM_RE      = re.compile(r'[?&]([a-zA-Z0-9_\[\]\.]{1,40})=')
OBJLIT_RE      = re.compile(r'(?:params|query|body|data|payload)\s*[:=]\s*\{([^{}]{0,600})\}', re.I)
OBJKEY_RE      = re.compile(r'''["']?([a-zA-Z_$][a-zA-Z0-9_$]{0,40})["']?\s*:''')
PARAM_ACCESS_RE= re.compile(r'\b(?:query|params|body|payload|args)\.([a-zA-Z_$][a-zA-Z0-9_$]{0,40})\b(?!\s*\()')
PARAM_STOPWORDS = {"get","set","has","delete","append","tostring","valueof",
                    "hasownproperty","keys","values","entries","foreach",
                    "map","filter","reduce","constructor","then","catch","finally","length"}
PARAM_GET_RE   = re.compile(r'''(?:params|query|searchParams)\.get\(["']([a-zA-Z0-9_\-.]{1,40})["']\)''')
FORMDATA_RE    = re.compile(r'''(?:formData|form)\.(?:append|set)\(["']([a-zA-Z0-9_\-.]{1,40})["']''', re.I)
DESTRUCTURE_RE = re.compile(r'\{\s*([^{}]{1,300}?)\s*\}\s*=\s*(?:[\w.]*\.)?(?:query|body|params)\b')

INTERESTING_RE = re.compile(
    r'(admin|internal|debug|staging|sandbox|backup|\.bak\b|config|swagger|openapi|'
    r'graphql|\.git\b|\.env\b|actuator|console|private|secret|dump|export|migrate|'
    r'impersonat|sudo|superuser|reset[-_]?password|forgot[-_]?password|'
    r'api/v[0-9]+/(?:users?|accounts?|admin)|token|credential|\.sql\b|\.log\b|'
    r'phpinfo|wp-config|\.htpasswd|id_rsa|shell|upload|xxe|ssrf)', re.I)

# Hardcoded — not configurable on the CLI (kept simple on purpose).
SKIP_EXTENSIONS = {"woff", "css", "png", "svg", "jpg", "woff2", "jpeg", "gif"}

def get_extension(target):
    t = target.split("?", 1)[0].split("#", 1)[0]
    try:
        s = urlsplit(t)
        if s.scheme and s.netloc:
            t = s.path
    except Exception:
        pass
    last_seg = t.rsplit("/", 1)[-1]
    if "." in last_seg:
        return last_seg.rsplit(".", 1)[-1].lower()
    return ""

SECRET_PATTERNS = {
    "AWS Access Key ID":        (r'AKIA[0-9A-Z]{16}', "high"),
    "AWS Secret Access Key":    (r'''(?i)aws(?:_|-)?(?:secret)?(?:_|-)?(?:access)?(?:_|-)?key(?:_|-)?(?:id)?["']?\s*[:=]\s*["'][A-Za-z0-9/+=]{40}["']''', "med"),
    "Google API Key":           (r'AIza[0-9A-Za-z\-_]{35}', "high"),
    "Google OAuth Token":       (r'ya29\.[0-9A-Za-z\-_]{20,}', "high"),
    "Firebase Server Key":      (r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{100,}', "high"),
    "Slack Token":              (r'xox[baprs]-[0-9A-Za-z-]{10,48}', "high"),
    "Slack Webhook":            (r'https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+', "high"),
    "Stripe Live Secret Key":   (r'sk_live_[0-9a-zA-Z]{20,}', "high"),
    "Stripe Live Publishable":  (r'pk_live_[0-9a-zA-Z]{20,}', "high"),
    "GitHub Token":             (r'gh[pousr]_[0-9A-Za-z]{36,}', "high"),
    "GitHub Fine-grained PAT":  (r'github_pat_[0-9A-Za-z_]{20,}', "high"),
    "JWT":                      (r'eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}', "high"),
    "Twilio API Key SID":       (r'SK[0-9a-fA-F]{32}', "med"),
    "Twilio Account SID":       (r'AC[0-9a-fA-F]{32}', "med"),
    "Mailgun API Key":          (r'key-[0-9a-zA-Z]{32}', "med"),
    "Mailchimp API Key":        (r'[0-9a-f]{32}-us[0-9]{1,2}', "high"),
    "Square Access Token":      (r'sq0(?:atp|csp)-[0-9A-Za-z\-_]{22,43}', "high"),
    "Braintree/PayPal Token":   (r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}', "high"),
    "Private Key Block":        (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----', "high"),
    "Basic Auth in URL":        (r'https?://[^:/\s"\']+:[^@/\s"\']+@[^\s"\']+', "high"),
    "Generic API Key Assign":   (r'''(?i)\b(?:api|app)[_-]?key["']?\s*[:=]\s*["'][0-9A-Za-z\-_]{16,45}["']''', "low"),
    "Generic Secret Assign":    (r'''(?i)\bsecret["']?\s*[:=]\s*["'][0-9A-Za-z\-_/+=]{16,45}["']''', "low"),
    "Hardcoded Bearer Token":   (r'''(?i)["']Bearer\s+[A-Za-z0-9\-_.]{20,}["']''', "low"),
}

# ───────────────────────── mode handling ─────────────────────────

VALID_MODES = {"all", "paths", "urls", "secrets", "map"}

def parse_modes(raw):
    tokens = {t.strip().lower() for t in raw.split(",") if t.strip()}
    bad = tokens - VALID_MODES
    if bad:
        sys.exit(f"{R}[!] Invalid mode(s): {', '.join(sorted(bad))}. "
                  f"Valid: {', '.join(sorted(VALID_MODES))} (comma-separate for multiple){X}")
    return tokens or {"all"}

def resolve_show(modes):
    """Returns (show-dict, map_flag). 'map' with nothing else defaults to
    paths+urls+secrets, since map has nothing to attribute otherwise."""
    if "all" in modes:
        return {"paths": True, "urls": True, "secrets": True,
                "params": True, "sourcemaps": True}, True
    show = {"paths": "paths" in modes, "urls": "urls" in modes,
             "secrets": "secrets" in modes, "params": False, "sourcemaps": False}
    map_flag = "map" in modes
    if map_flag and not (show["paths"] or show["urls"] or show["secrets"]):
        show["paths"] = show["urls"] = show["secrets"] = True
    return show, map_flag

# ───────────────────────── helpers ─────────────────────────

def read_lines(f):
    p = Path(f)
    if not p.exists():
        sys.exit(f"{R}[!] File not found: {f}{X}")
    return [x.strip() for x in p.read_text(errors="ignore").splitlines()
            if x.strip() and not x.lstrip().startswith("#")]

def load_scope(s):
    if not s:
        return [], []
    p = Path(s)
    tokens = read_lines(s) if p.exists() and p.is_file() else re.split(r'[,\s]+', s.strip())
    inc, exc = [], []
    for x in tokens:
        x = x.strip()
        if not x or x.startswith("#"):
            continue
        neg = x.startswith("!")
        x = x[1:].strip() if neg else x
        x = re.sub(r'^[a-z]+://', '', x, flags=re.I).split("/", 1)[0].split(":", 1)[0].lower().rstrip(".")
        if x.startswith("*."):
            x = x[2:]
        if x:
            (exc if neg else inc).append(x)
    return sorted(set(inc)), sorted(set(exc))

def in_scope(host, inc, exc):
    h = (host or "").lower().rstrip(".")
    if any(h == d or h.endswith("." + d) for d in exc):
        return False
    return not inc or any(h == d or h.endswith("." + d) for d in inc)

_IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

def clean_url(x):
    x = html.unescape(x).strip().rstrip(".,;")
    if x.startswith("//"):
        x = "https:" + x
    try:
        s = urlsplit(x)
        if s.scheme.lower() not in ("http", "https") or not s.netloc:
            return None
        host = (s.hostname or "")
        if host != "localhost" and not _IP_RE.match(host) and "." not in host:
            return None
        return urlunsplit((s.scheme.lower(), s.netloc.lower(), s.path or "/", s.query, ""))
    except Exception:
        return None

def clean_path(x):
    x = html.unescape(x).strip().rstrip(".,;").split("#", 1)[0]
    if not x or not x.startswith("/") or x.startswith("//") or BAD_PATH.search(x):
        return None
    if any(ord(c) < 32 for c in x):
        return None
    return x

def decode_obfuscation(data):
    try:
        d = UNI_ESC.sub(lambda m: chr(int(m.group(1), 16)), data)
        d = HEX_ESC.sub(lambda m: chr(int(m.group(1), 16)), d)
        return d
    except Exception:
        return data

def fetch(url, timeout, retries, delay):
    marker = "\n__JSRECON_STATUS__:"
    for attempt in range(retries + 1):
        try:
            p = subprocess.run(
                ["curl", "-skL", "--compressed", "--max-time", str(timeout),
                 "-A", "Mozilla/5.0 JSRecon/5.0",
                 "-w", marker + "%{http_code}", url],
                capture_output=True, text=True, errors="ignore")
            out = p.stdout
            if marker in out:
                body, code = out.rsplit(marker, 1)
                code = code.strip()
            else:
                body, code = out, None
            if body and (code is None or code.startswith(("2", "3"))):
                return body, code
            if attempt == retries:
                return body, code
        except FileNotFoundError:
            sys.exit(f"{R}[!] curl is required.{X}")
        except Exception:
            pass
        if attempt < retries:
            time.sleep(delay + random.uniform(0, 0.4) + attempt * 0.5)
    return "", None

def read_local(path):
    try:
        return Path(path).read_text(errors="ignore"), "200"
    except Exception:
        return "", None

def looks_like_html_document(data):
    """Filters out soft-200 HTML (homepage/error templates) served from a
    .js path, so it isn't scanned as if it were real JavaScript."""
    if not data:
        return False
    head = data.lstrip("\ufeff \t\r\n").lower()[:4096]
    if head.startswith("<!doctype html") or head.startswith("<html"):
        return True
    if re.search(r"<html(?:\s|>)", head, re.I):
        return True
    if re.search(r"<head(?:\s|>)", head, re.I) and re.search(r"<body(?:\s|>)", head, re.I):
        return True
    return False

# ───────────────────────── extraction ─────────────────────────

def extract_paths_urls(data, inc, exc, aggressive):
    ps_strict, us, ps_loose = set(), set(), set()
    for variant in (data, decode_obfuscation(data)):
        for m in PATH_RE.finditer(variant):
            p = clean_path(m.group(1))
            if p:
                ps_strict.add(p)
        for m in URL_RE.finditer(variant):
            u = clean_url(m.group(0))
            if u and in_scope(urlsplit(u).hostname, inc, exc):
                us.add(u)
        if aggressive:
            for m in LOOSE_PATH_RE.finditer(variant):
                if REGEX_LITERAL_CTX.search(variant[max(0, m.start()-20):m.start()]):
                    continue
                p = clean_path(m.group(0))
                if p and any(c.isalpha() for c in p):
                    ps_loose.add(p)
    ps_loose -= ps_strict
    ps = ps_strict | ps_loose
    return ps, us, ps_loose

def extract_secrets(data, source):
    hits = []
    for name, (pat, conf) in SECRET_PATTERNS.items():
        for m in re.finditer(pat, data):
            val = m.group(0)
            snippet = val if len(val) <= 80 else val[:77] + "..."
            hits.append((conf, name, snippet, source))
    return hits

def extract_sourcemaps(data, source_url):
    out = set()
    for m in SOURCEMAP_RE.finditer(data):
        ref = m.group(1).strip()
        if ref.startswith("data:"):
            continue
        out.add(urljoin(source_url, ref))
    return out

def extract_params(data, ps, us):
    names = set()
    for target in list(ps) + list(us):
        for m in QPARAM_RE.finditer(target):
            names.add(m.group(1))
    for m in QPARAM_RE.finditer(data):
        names.add(m.group(1))
    for blk in OBJLIT_RE.finditer(data):
        for m in OBJKEY_RE.finditer(blk.group(1)):
            names.add(m.group(1))
    for m in PARAM_ACCESS_RE.finditer(data):
        tok = m.group(1)
        if tok.lower() not in PARAM_STOPWORDS:
            names.add(tok)
    for m in PARAM_GET_RE.finditer(data):
        names.add(m.group(1))
    for m in FORMDATA_RE.finditer(data):
        names.add(m.group(1))
    for blk in DESTRUCTURE_RE.finditer(data):
        for tok in blk.group(1).split(","):
            tok = tok.strip().split(":")[0].split("=")[0].strip()
            if re.match(r'^[A-Za-z_$][A-Za-z0-9_$]*$', tok):
                names.add(tok)
    names.discard("")
    return names

def flag_interesting(items):
    return set(x for x in items if INTERESTING_RE.search(x))

# ───────────────────────── live categorized output ─────────────────────────

def print_target_report(src, ok, ps, us, ps_loose, secrets, smaps, params, interesting, show):
    status = f"{G}OK{X}" if ok else f"{R}FAIL{X}"
    print(f"\n{C}==>{X} [{status}] {src}")
    if not ok:
        return
    shown_anything = False
    if show["urls"] and us:
        shown_anything = True
        print(f"{M}  URLS ({len(us)}):{X}")
        for u in sorted(us):
            tag = f" {Y}[interesting]{X}" if u in interesting else ""
            print(f"    {u}{tag}")
    if show["paths"]:
        core_paths = ps - ps_loose
        if core_paths:
            shown_anything = True
            print(f"{B}  PATHS ({len(core_paths)}):{X}")
            for p in sorted(core_paths):
                tag = f" {Y}[interesting]{X}" if p in interesting else ""
                print(f"    {p}{tag}")
        if ps_loose:
            shown_anything = True
            print(f"{D}  PATHS — loose/unverified ({len(ps_loose)}):{X}")
            for p in sorted(ps_loose):
                print(f"    {p}")
    if show["secrets"] and secrets:
        shown_anything = True
        print(f"{O}  SECRETS ({len(secrets)}) — candidates only, verify before reporting:{X}")
        for conf, name, snippet, _ in secrets:
            print(f"    [{conf.upper()}] {name}: {snippet}")
    if show["params"] and params:
        shown_anything = True
        print(f"{W}  PARAMS ({len(params)}):{X} {', '.join(sorted(params))}")
    if show["sourcemaps"] and smaps:
        shown_anything = True
        print(f"{G}  SOURCEMAPS ({len(smaps)}):{X}")
        for sm in sorted(smaps):
            print(f"    {sm}")
    if not shown_anything:
        print(f"  {D}(nothing found){X}")

# ───────────────────────── scan orchestration ─────────────────────────

class Results:
    def __init__(self):
        self.lock = threading.Lock()
        self.paths, self.urls, self.secrets = set(), set(), []
        self.sourcemaps, self.params = set(), set()
        self.mapping, self.url_mapping = [], []
        self.loose_paths = set()
        self.done, self.errors = 0, []

def scan_one(src, args, inc, exc):
    body, code = (read_local(src) if args.local else
                  fetch(src, args.timeout, args.retries, args.delay))
    if body and looks_like_html_document(body):
        body = ""
    ps, us, ps_loose, smaps, params, secrets = set(), set(), set(), set(), set(), []
    if body:
        ps, us, ps_loose = extract_paths_urls(body, inc, exc, args.aggressive)
        if not args.no_secrets:
            secrets = extract_secrets(body, src)
        if not args.no_sourcemap:
            smaps = extract_sourcemaps(body, src)
        params = extract_params(body, ps, us)
    interesting = flag_interesting(ps) | flag_interesting(us)
    return {"src": src, "body": body, "code": code, "paths": ps, "urls": us,
            "loose_paths": ps_loose, "sourcemaps": smaps, "params": params,
            "secrets": secrets, "interesting": interesting}

def _merge_result(res, item):
    res.paths.update(item["paths"]); res.urls.update(item["urls"])
    res.loose_paths.update(item["loose_paths"])
    res.secrets.extend(item["secrets"]); res.sourcemaps.update(item["sourcemaps"])
    res.params.update(item["params"])
    res.mapping += [(p, item["src"]) for p in item["paths"]]
    res.url_mapping += [(u, item["src"]) for u in item["urls"]]
    res.done += 1
    if not item["body"]:
        res.errors.append(item["src"])

def _has_hit(item, show):
    return bool(
        (show["paths"] and item["paths"]) or
        (show["urls"] and item["urls"]) or
        (show["secrets"] and item["secrets"]) or
        (show["params"] and item["params"]) or
        (show["sourcemaps"] and item["sourcemaps"])
    )

def scan(targets, args, inc, exc, show, res=None, label=""):
    """Fetches concurrently; PRINTS strictly in input order so [n/total]
    always matches the target's position in the list being scanned."""
    if res is None:
        res = Results()
    total = len(targets)
    with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = [ex.submit(scan_one, t, args, inc, exc) for t in targets]
        for idx, fut in enumerate(futures, 1):
            try:
                item = fut.result()
            except Exception:
                item = {"src": targets[idx - 1], "body": "", "code": 0,
                        "paths": set(), "urls": set(), "loose_paths": set(),
                        "sourcemaps": set(), "params": set(), "secrets": [],
                        "interesting": set()}
            _merge_result(res, item)
            found = _has_hit(item, show)
            if args.silent and not found:
                continue
            print(f"{D}{label}[{idx}/{total}]{X}", end="")
            print_target_report(item["src"], bool(item["body"]), item["paths"], item["urls"],
                                 item["loose_paths"], item["secrets"], item["sourcemaps"],
                                 item["params"], item["interesting"], show)
    return res

# ───────────────────────── source-map follow-up ─────────────────────────

def resolve_sourcemap_sources(smap_urls, args, inc, exc):
    found = {}
    for u in sorted(smap_urls):
        host = urlsplit(u).hostname
        if not in_scope(host, inc, exc):
            continue
        body, _ = fetch(u, args.timeout, 1, args.delay)
        if not body:
            continue
        try:
            j = json.loads(body)
            srcs = j.get("sources") or []
            if srcs:
                found[u] = srcs
        except Exception:
            continue
    return found

# ───────────────────────── diff mode ─────────────────────────

def do_diff(baseline_file, current_items):
    old = set(read_lines(baseline_file)) if Path(baseline_file).exists() else set()
    return sorted(current_items - old)

# ───────────────────────── output ─────────────────────────

def save(path, lines):
    Path(path).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

def format_secrets(secrets):
    out = []
    for label, conf in (("HIGH — tight format, low false-positive rate", "high"),
                         ("MEDIUM — structured but has legitimate lookalikes", "med"),
                         ("LOW — generic shape, expect noise, verify by hand", "low")):
        rows = [s for s in secrets if s[0] == conf]
        if not rows:
            continue
        out.append(f"# {label} ({len(rows)})")
        for c, name, snippet, src in sorted(rows, key=lambda r: r[1]):
            out.append(f"{name}: {snippet}  (source: {src})")
        out.append("")
    return out

def main():
    print_banner()
    ap = argparse.ArgumentParser(description="Sudarshana v5 — concurrent JS path/URL/secret recon")
    ap.add_argument("-m", "--mode", default="all",
                     help="comma-separated: all,paths,urls,secrets,map — e.g. -m urls,secrets")
    ap.add_argument("-i", "--input", default="js.txt", help="file of JS URLs (or local paths with --local), one per line")
    ap.add_argument("-o", "--outdir", default=None,
                     help="directory to persist results into. Omit to only print to the terminal.")
    ap.add_argument("-s", "--scope", default=None,
                     help="scope file OR domain(s) directly, e.g. -s example.com or -s 'example.com,!admin.example.com'")
    ap.add_argument("-t", "--timeout", type=int, default=20)
    ap.add_argument("-c", "--threads", type=int, default=4, help="concurrent fetch workers (default 4)")
    ap.add_argument("--delay", type=float, default=0.0, help="base delay before a retry, per worker")
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--local", action="store_true", help="treat --input lines as local file paths, not URLs")
    ap.add_argument("--aggressive", action="store_true",
                     help="also catch unquoted/loosely-delimited paths. Higher false-positive rate.")
    ap.add_argument("--no-secrets", action="store_true")
    ap.add_argument("--no-sourcemap", action="store_true")
    ap.add_argument("--resolve-sourcemaps", action="store_true", help="fetch discovered .map files and list original source paths")
    ap.add_argument("--json", action="store_true", help="also write results.json (requires -o)")
    ap.add_argument("--diff", metavar="BASELINE", help="compare against a previous run's saved list (requires -o)")
    ap.add_argument("--no-follow", action="store_true", help="don't auto-scan .js URLs discovered inside scanned JS files")
    ap.add_argument("--silent", "-silent", action="store_true",
                     help="hide failed/empty targets from live output; real hits still show, in js.txt order. "
                          "Registered under both spellings since a single dash is easy to type by habit.")
    a = ap.parse_args()

    modes = parse_modes(a.mode)
    show, map_flag = resolve_show(modes)
    inc, exc = load_scope(a.scope)
    run_ts = datetime.now().strftime("%d-%m-%Y-%H%M%S")

    print(f"{C}[*] Mode:{X} {','.join(sorted(modes))}"
          + (f"  {D}(map: on){X}" if map_flag else ""))
    print(f"{C}[*] Scope:{X} {a.scope or 'OFF — all discovered URLs'}"
          + (f"  {D}(parsed as: {', '.join(inc) or '-'}{' | excl: '+', '.join(exc) if exc else ''}){X}" if a.scope else ""))
    print(f"{C}[*] Threads:{X} {a.threads}  {C}Retries:{X} {a.retries}  "
          f"{C}Source:{X} {'local files' if a.local else 'remote fetch'}  "
          f"{C}Save:{X} {a.outdir if a.outdir else D+'off (console only)'+X}")

    targets_all = list(dict.fromkeys(read_lines(a.input)))
    if not targets_all:
        sys.exit(f"{R}[!] No targets in {a.input}{X}")

    skipped = [t for t in targets_all if get_extension(t) in SKIP_EXTENSIONS]
    targets = [t for t in targets_all if get_extension(t) not in SKIP_EXTENSIONS]
    if skipped:
        print(f"{D}[*] Skipping {len(skipped)} static asset(s) by extension ({', '.join(sorted(SKIP_EXTENSIONS))}){X}")
    if not targets:
        sys.exit(f"{R}[!] Nothing left to scan after extension filtering ({len(skipped)} skipped){X}")

    t0 = time.time()
    res = scan(targets, a, inc, exc, show)

    # ── follow one level of JS-referencing-JS links ──
    known = set(targets_all) | set(skipped)
    discovered_js = set()
    if not a.no_follow and not a.local:
        for u in res.urls:
            if get_extension(u) == "js" and u not in known:
                discovered_js.add(u)
        for p, src in res.mapping:
            if get_extension(p) == "js":
                try:
                    full = urljoin(src, p)
                    if full not in known:
                        discovered_js.add(full)
                except Exception:
                    pass
        discovered_js = {u for u in discovered_js if in_scope(urlsplit(u).hostname, inc, exc)}
    elif a.local and not a.no_follow:
        print(f"{D}[*] --local run: skipping JS-link follow-up (no live URLs to fetch).{X}")

    if discovered_js:
        print(f"\n{Y}[*] Following {len(discovered_js)} newly discovered JS link(s)...{X}")
        res = scan(sorted(discovered_js), a, inc, exc, show, res=res, label="[new] ")

    elapsed = time.time() - t0
    interesting_all = flag_interesting(res.paths) | flag_interesting(res.urls)

    if a.outdir:
        outdir = Path(a.outdir); outdir.mkdir(parents=True, exist_ok=True)

        def out(name):
            return outdir / f"{name}-{run_ts}.txt"

        if skipped:
            save(out("skipped-ext"), skipped)
        if discovered_js:
            save(out("new-js-urls"), sorted(discovered_js))

        if show["paths"]:
            if map_flag:
                save(out("paths"), [f"{p}\t{s}" for p, s in sorted(set(res.mapping))])
            else:
                save(out("paths"), sorted(res.paths))
        if show["urls"]:
            if map_flag:
                save(out("urls"), [f"{u}\t{s}" for u, s in sorted(set(res.url_mapping))])
            else:
                save(out("urls"), sorted(res.urls))
        if show["secrets"]:
            save(out("secrets"), format_secrets(res.secrets))
        if show["params"]:
            save(out("params"), sorted(res.params))
        if show["sourcemaps"]:
            save(out("sourcemaps"), sorted(res.sourcemaps))
        if "all" in modes:
            save(out("interesting"), sorted(interesting_all))
            if res.errors:
                save(out("errors"), res.errors)
            if a.aggressive:
                save(out("paths-loose"), sorted(res.loose_paths))
            smap_sources = {}
            if a.resolve_sourcemaps and res.sourcemaps:
                print(f"{Y}[*] Resolving {len(res.sourcemaps)} source map(s)...{X}")
                smap_sources = resolve_sourcemap_sources(res.sourcemaps, a, inc, exc)
                lines = []
                for u, srcs in smap_sources.items():
                    lines.append(f"# {u}"); lines.extend(srcs)
                save(out("sourcemap-sources"), lines)
            if a.diff:
                save(out("new-findings"), do_diff(a.diff, res.paths | res.urls))
            if a.json:
                payload = {
                    "scanned": len(targets), "elapsed_seconds": round(elapsed, 2),
                    "paths": sorted(res.paths), "urls": sorted(res.urls),
                    "loose_paths": sorted(res.loose_paths),
                    "interesting": sorted(interesting_all), "params": sorted(res.params),
                    "secrets": [{"confidence": c, "type": n, "match": s, "source": src} for c, n, s, src in res.secrets],
                    "sourcemaps": sorted(res.sourcemaps), "sourcemap_sources": smap_sources,
                    "discovered_js": sorted(discovered_js), "errors": res.errors,
                }
                (out("results").with_suffix(".json")).write_text(json.dumps(payload, indent=2))
        print(f"{G}[+] Results written to {outdir}/ (timestamp {run_ts}){X}")
    else:
        print(f"{D}[*] No -o given — nothing written to disk, results shown above only.{X}")

    print(f"\n{G}========== COMPLETE ({elapsed:.1f}s) =========={X}")
    print(f"{C}JS files scanned :{X} {res.done}  ({R}{len(res.errors)} failed{X})"
          + (f"  {D}({len(skipped)} skipped by ext, {len(discovered_js)} followed){X}" if skipped or discovered_js else ""))
    print(f"{G}Unique paths     :{X} {len(res.paths)}  ({D}{len(res.loose_paths)} loose{X})  {Y}({len(flag_interesting(res.paths))} interesting){X}")
    print(f"{M}Unique URLs      :{X} {len(res.urls)}   {Y}({len(flag_interesting(res.urls))} interesting){X}")
    print(f"{O}Candidate secrets:{X} {len(res.secrets)}  {D}(unverified — see confidence labels){X}")
    print(f"{B}Source maps      :{X} {len(res.sourcemaps)}")
    print(f"{W}Param names      :{X} {len(res.params)}")

if __name__ == "__main__":
    main()