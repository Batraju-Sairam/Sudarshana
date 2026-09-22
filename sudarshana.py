#!/usr/bin/env python3
"""
JSRecon v5 — concurrent JS reconnaissance for bug bounty workflows.

- Modes (-m): all, paths, urls, secrets, map — comma-separated, e.g. -m urls,secrets
  Modes are STRICT: only the extraction functions needed for the selected
  categories run at all. The one exception is JS-link discovery for the
  recursive crawler (see note 3 below).
- Live output shows a running "[scanned/total] ... remaining ... failed"
  progress line for every completed target, plus a detailed per-target
  report unless --silent is set and the target had no hit.
- Nothing is written to disk unless -o is given. Results are streamed to
  disk AS SOON AS each JS target finishes (not batched until the end), so
  a killed/crashed run still leaves partial results on disk. A final pass
  rewrites the same files with clean, deduplicated, sorted content.
- -o accepts either a directory name (e.g. `-o results`) or an explicit
  file path with a recognized extension (e.g. `-o paths.txt`,
  `-o results/paths.txt`). See build_output_paths()/ResultWriter below.
- Follows JS-referencing-JS links discovered inside scanned files
  (respecting --scope if given) using a single dynamic work queue instead
  of discrete "waves", so newly discovered files are scanned immediately
  alongside whatever is still in flight, with accurate progress counters.
  NOTE: because mode selection also gates which regexes run, recursion
  coverage depends on mode. With "paths" selected, absolute JS URLs are
  still detected internally purely to keep following links (never shown
  as URL results). With "urls" selected, relative JS paths are not
  scanned for (no path regex runs), so only absolute-URL-based recursion
  happens. With a mode that includes neither ("secrets" alone, say),
  no link-discovery regex runs at all, so recursion will not extend past
  whatever was in the input file. Include "paths" and/or "urls" in your
  mode if you want full recursive coverage.
"""
import argparse, concurrent.futures as cf, html, json, os, random, re, subprocess
import sys, time
from collections import deque
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

def normalize_domain_token(x):
    """Turns example.com / *.example.com / *example.com / .example.com
    all into the bare domain 'example.com', so downstream matching is a
    single consistent domain/subdomain check rather than ad-hoc wildcard
    handling (and never an unsafe substring match)."""
    x = x.strip()
    if not x:
        return ""
    x = re.sub(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://', '', x)   # strip scheme
    x = x.split("/", 1)[0].split(":", 1)[0]               # strip path/port
    if x.startswith("*."):
        x = x[2:]
    elif x.startswith("*"):
        x = x[1:]
    if x.startswith("."):
        x = x[1:]
    return x.lower().rstrip(".")

def load_scope(s):
    if not s:
        return [], []
    p = Path(s)
    tokens = read_lines(s) if p.exists() and p.is_file() else re.split(r'[,\s]+', s.strip())
    inc, exc = [], []
    for tok in tokens:
        tok = tok.strip()
        if not tok or tok.startswith("#"):
            continue
        neg = tok.startswith("!")
        if neg:
            tok = tok[1:].strip()
        d = normalize_domain_token(tok)
        if d:
            (exc if neg else inc).append(d)
    return sorted(set(inc)), sorted(set(exc))

def in_scope(host, inc, exc):
    """Domain/subdomain match only — never a substring match. This is why
    'example.com.evil.com', 'notexample.com' and 'evil-example.com' never
    match a scope of 'example.com' (or any of its wildcard spellings),
    while 'www.example.com' and 'dev.api.example.com' do."""
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
#
# Paths and URLs are now extracted by two SEPARATE functions (rather than
# one combined pass) specifically so mode selection can gate each regex
# independently — see the "run_paths_regex" / "run_url_regex" logic in
# scan_one() below.

def extract_paths(data, aggressive):
    ps_strict, ps_loose = set(), set()
    for variant in (data, decode_obfuscation(data)):
        for m in PATH_RE.finditer(variant):
            p = clean_path(m.group(1))
            if p:
                ps_strict.add(p)
        if aggressive:
            for m in LOOSE_PATH_RE.finditer(variant):
                if REGEX_LITERAL_CTX.search(variant[max(0, m.start()-20):m.start()]):
                    continue
                p = clean_path(m.group(0))
                if p and any(c.isalpha() for c in p):
                    ps_loose.add(p)
    ps_loose -= ps_strict
    return ps_strict | ps_loose, ps_loose

def extract_urls(data, inc, exc):
    us = set()
    for variant in (data, decode_obfuscation(data)):
        for m in URL_RE.finditer(variant):
            u = clean_url(m.group(0))
            if u and in_scope(urlsplit(u).hostname, inc, exc):
                us.add(u)
    return us

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
    print(f"{C}==>{X} [{status}] {src}")
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
        self.paths, self.urls, self.secrets = set(), set(), []
        self.sourcemaps, self.params = set(), set()
        self.mapping, self.url_mapping = [], []      # (item, source) pairs, only when map_flag
        self.mapping_seen = set()                     # dedup for the above during streaming
        self.loose_paths = set()
        self.done, self.errors = 0, []

def scan_one(src, args, inc, exc, show, need_link_discovery):
    """Fetches one target and extracts ONLY what the selected mode (show)
    requires. The one exception: if recursive JS-following is active,
    whichever of path/url detection is needed purely to keep discovering
    new JS links still runs internally, but anything not in `show` is
    never merged into the reported/streamed results — see js_candidates."""
    body, code = (read_local(src) if args.local else
                  fetch(src, args.timeout, args.retries, args.delay))
    if body and looks_like_html_document(body):
        body = ""
    ok = bool(body)
    ps, us, ps_loose = set(), set(), set()
    smaps, params, secrets = set(), set(), []
    js_candidates = set()

    if body:
        run_paths_regex = show["paths"]
        # Exception: when "paths" is selected but "urls" is not, and we're
        # still following JS links, we also need to notice absolute JS
        # URLs internally — purely so recursion doesn't stall — without
        # ever treating them as requested URL results.
        run_url_regex = show["urls"] or (need_link_discovery and show["paths"] and not show["urls"])

        ps_all, ps_loose_all = extract_paths(body, args.aggressive) if run_paths_regex else (set(), set())
        us_all = extract_urls(body, inc, exc) if run_url_regex else set()

        ps = ps_all if show["paths"] else set()
        ps_loose = ps_loose_all if show["paths"] else set()
        us = us_all if show["urls"] else set()

        if need_link_discovery:
            for u in us_all:
                if get_extension(u) == "js":
                    js_candidates.add(u)
            for p in ps_all:
                if get_extension(p) == "js":
                    full = clean_url(urljoin(src, p))
                    if full:
                        js_candidates.add(full)
            if js_candidates:
                js_candidates = {u for u in js_candidates if in_scope(urlsplit(u).hostname, inc, exc)}

        if not args.no_secrets and show["secrets"]:
            secrets = extract_secrets(body, src)
        if not args.no_sourcemap and show["sourcemaps"]:
            smaps = extract_sourcemaps(body, src)
        if show["params"]:
            params = extract_params(body, ps_all, us_all)

    interesting = flag_interesting(ps) | flag_interesting(us)
    body = None  # don't hold the response text in memory once extraction is done

    return {"src": src, "ok": ok, "paths": ps, "urls": us, "loose_paths": ps_loose,
            "sourcemaps": smaps, "params": params, "secrets": secrets,
            "interesting": interesting, "js_candidates": js_candidates}

def _has_hit(item, show):
    return bool(
        (show["paths"] and item["paths"]) or
        (show["urls"] and item["urls"]) or
        (show["secrets"] and item["secrets"]) or
        (show["params"] and item["params"]) or
        (show["sourcemaps"] and item["sourcemaps"])
    )

def _merge_and_stream(res, item, writer, show, map_flag):
    """Folds one target's results into the running totals AND streams the
    newly-seen items straight to disk (if -o was given), so they survive
    even if the process is killed before the scan finishes."""
    src = item["src"]
    res.done += 1
    if not item["ok"]:
        res.errors.append(src)

    if show["paths"] and item["paths"]:
        new_plain = item["paths"] - res.paths
        if map_flag:
            new_rows = [(p, src) for p in item["paths"] if (p, src) not in res.mapping_seen]
            for row in new_rows:
                res.mapping_seen.add(row)
                res.mapping.append(row)
            writer.stream_items("paths", [f"{p}\t{s}" for p, s in new_rows])
        else:
            writer.stream_items("paths", sorted(new_plain))
        res.paths.update(item["paths"])
    if show["paths"] and item["loose_paths"]:
        res.loose_paths.update(item["loose_paths"])

    if show["urls"] and item["urls"]:
        new_plain_u = item["urls"] - res.urls
        if map_flag:
            new_rows_u = [(u, src) for u in item["urls"] if (u, src) not in res.mapping_seen]
            for row in new_rows_u:
                res.mapping_seen.add(row)
                res.url_mapping.append(row)
            writer.stream_items("urls", [f"{u}\t{s}" for u, s in new_rows_u])
        else:
            writer.stream_items("urls", sorted(new_plain_u))
        res.urls.update(item["urls"])

    if show["secrets"] and item["secrets"]:
        res.secrets.extend(item["secrets"])
        writer.stream_secrets(item["secrets"])

    if show["sourcemaps"] and item["sourcemaps"]:
        new_sm = item["sourcemaps"] - res.sourcemaps
        if new_sm:
            writer.stream_items("sourcemaps", sorted(new_sm))
        res.sourcemaps.update(item["sourcemaps"])

    if show["params"] and item["params"]:
        new_pr = item["params"] - res.params
        if new_pr:
            writer.stream_items("params", sorted(new_pr))
        res.params.update(item["params"])

def run_engine(targets, targets_all, skipped, args, inc, exc, show, map_flag,
               need_link_discovery, writer):
    """Single dynamic work queue: initial targets plus every recursively
    discovered in-scope JS link are processed through one bounded thread
    pool, so progress counters ('[scanned/total] ... remaining') stay
    accurate even as new links are discovered mid-scan, and we never hold
    Futures for the whole (potentially huge) target list at once."""
    res = Results()
    known = set(targets_all) | set(skipped)
    followed_js = {u for u in known if get_extension(u) == "js"}
    discovered_js = set()

    to_process = deque(targets)
    total = len(targets)
    scanned = 0
    failed = 0

    window = max(args.threads * 2, args.threads, 1)
    pending = {}
    executor = cf.ThreadPoolExecutor(max_workers=args.threads)

    def submit_next():
        if to_process:
            t = to_process.popleft()
            fut = executor.submit(scan_one, t, args, inc, exc, show, need_link_discovery)
            pending[fut] = t

    try:
        for _ in range(min(window, len(to_process))):
            submit_next()

        while pending:
            done, _ = cf.wait(list(pending.keys()), return_when=cf.FIRST_COMPLETED)
            for fut in done:
                src = pending.pop(fut)
                try:
                    item = fut.result()
                except Exception:
                    item = {"src": src, "ok": False, "paths": set(), "urls": set(),
                            "loose_paths": set(), "sourcemaps": set(), "params": set(),
                            "secrets": [], "interesting": set(), "js_candidates": set()}

                scanned += 1
                if not item["ok"]:
                    failed += 1
                is_new = src in discovered_js

                _merge_and_stream(res, item, writer, show, map_flag)

                new_candidates = set()
                if need_link_discovery:
                    for cand in item["js_candidates"]:
                        if cand not in followed_js:
                            followed_js.add(cand)
                            discovered_js.add(cand)
                            new_candidates.add(cand)
                            to_process.append(cand)
                            total += 1

                found = _has_hit(item, show)
                show_detail = (not args.silent) or found
                remaining = total - scanned
                progress = (f"{D}[{scanned}/{total}] scanned | {remaining} remaining"
                            + (f" | {failed} failed" if failed else "") + f"{X}")
                tag = f"{Y}[new]{X} " if is_new else ""
                if show_detail:
                    print(f"\n{tag}{progress}")
                    print_target_report(item["src"], item["ok"], item["paths"], item["urls"],
                                         item["loose_paths"], item["secrets"], item["sourcemaps"],
                                         item["params"], item["interesting"], show)
                else:
                    print(progress)

                if new_candidates:
                    print(f"{Y}[*] +{len(new_candidates)} new in-scope JS link(s) queued "
                          f"(total: {total}){X}")

                submit_next()
    finally:
        executor.shutdown(wait=True)

    res.done = scanned
    return res, scanned, failed, total, discovered_js

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

# ───────────────────────── -o : directory-or-file resolution ─────────────────────────

RECOGNIZED_OUTPUT_EXTS = {"txt", "json", "log", "out", "csv", "tsv", "md"}

def classify_output_target(raw):
    """A name with a recognized extension is a FILE. Anything else
    (including a bare name with no extension, like `results`) is a
    DIRECTORY — never a nested '<name>/<name>' file-inside-itself."""
    p = Path(raw)
    suffix = p.suffix.lstrip(".").lower()
    if suffix in RECOGNIZED_OUTPUT_EXTS:
        return "file", p
    return "dir", p

def build_output_paths(outdir_arg):
    if not outdir_arg:
        return None, None, None
    kind, p = classify_output_target(outdir_arg)
    if kind == "file":
        parent = p.parent
        if str(parent) in ("", "."):
            parent = Path(".")
        return "file", parent, p
    return "dir", p, None

class ResultWriter:
    """Owns the on-disk output for the run. During the scan, stream_items()/
    stream_secrets() append-and-flush(+fsync) newly discovered items the
    moment they're found. After the scan, main() calls finalize_main_outputs()
    which rewrites the same paths from scratch with clean, deduplicated,
    sorted content — using save(), independent of the streaming handles."""

    def __init__(self, kind, base_dir, explicit_file, show, run_ts):
        self.kind = kind
        self.base_dir = base_dir
        self.explicit_file = explicit_file
        self.run_ts = run_ts
        self.enabled = kind is not None
        self.handles = {}
        self.paths_for = {}
        self.combined_cats = []
        self._section_started = set()

        if not self.enabled:
            return
        if self.base_dir:
            self.base_dir.mkdir(parents=True, exist_ok=True)

        cats = [c for c in ("paths", "urls", "secrets", "params", "sourcemaps") if show.get(c)]

        if kind == "dir":
            for c in cats:
                path = self.base_dir / f"{c}-{run_ts}.txt"
                self.paths_for[c] = path
                self.handles[c] = open(path, "w", encoding="utf-8")
        else:  # explicit file — all selected categories share one file
            path = self.explicit_file
            self.paths_for["__combined__"] = path
            fh = open(path, "w", encoding="utf-8")
            self.combined_cats = cats
            for c in cats:
                self.handles[c] = fh

    def _write_line(self, cat, line):
        if not self.enabled or cat not in self.handles:
            return
        fh = self.handles[cat]
        if self.kind == "file" and len(self.combined_cats) > 1 and cat not in self._section_started:
            if self._section_started:
                fh.write("\n")
            fh.write(f"# ===== {cat.upper()} =====\n")
            self._section_started.add(cat)
        fh.write(line + "\n")
        try:
            fh.flush()
            os.fsync(fh.fileno())
        except Exception:
            pass

    def stream_items(self, cat, items):
        for it in items:
            self._write_line(cat, it)

    def stream_secrets(self, secrets):
        for conf, name, snippet, src in secrets:
            self._write_line("secrets", f"[{conf.upper()}] {name}: {snippet}  (source: {src})")

    def close_streams(self):
        seen = set()
        for fh in self.handles.values():
            if id(fh) not in seen:
                seen.add(id(fh))
                try:
                    fh.close()
                except Exception:
                    pass
        self.handles = {}

def finalize_main_outputs(writer, res, show, map_flag):
    if not writer.enabled:
        return
    content = {}
    if show["paths"]:
        content["paths"] = ([f"{p}\t{s}" for p, s in sorted(set(res.mapping))] if map_flag
                             else sorted(res.paths))
    if show["urls"]:
        content["urls"] = ([f"{u}\t{s}" for u, s in sorted(set(res.url_mapping))] if map_flag
                            else sorted(res.urls))
    if show["secrets"]:
        content["secrets"] = format_secrets(res.secrets)
    if show["params"]:
        content["params"] = sorted(res.params)
    if show["sourcemaps"]:
        content["sourcemaps"] = sorted(res.sourcemaps)

    if writer.kind == "dir":
        for cat, lines in content.items():
            if cat in writer.paths_for:
                save(writer.paths_for[cat], lines)
    else:
        combined_path = writer.paths_for.get("__combined__")
        if combined_path is None:
            return
        cats = writer.combined_cats
        multi = len(cats) > 1
        out_lines = []
        first = True
        for cat in cats:
            lines = content.get(cat, [])
            if not first:
                out_lines.append("")
            first = False
            if multi:
                out_lines.append(f"# ===== {cat.upper()} =====")
            out_lines.extend(lines)
        save(combined_path, out_lines)

def main():
    print_banner()
    ap = argparse.ArgumentParser(description="JSRecon v5 — concurrent JS path/URL/secret recon")
    ap.add_argument("-m", "--mode", default="all",
                     help="comma-separated: all,paths,urls,secrets,map — e.g. -m urls,secrets")
    ap.add_argument("-i", "--input", default="js.txt", help="file of JS URLs (or local paths with --local), one per line")
    ap.add_argument("-o", "--outdir", default=None,
                     help="where to save results. A bare name (e.g. `results`) or any name "
                          "without a recognized extension is treated as a DIRECTORY that gets "
                          "created, holding one <category>-<timestamp>.txt file per selected "
                          "mode. A name with a recognized extension (.txt/.json/.log/.out/.csv/"
                          ".tsv/.md), e.g. `paths.txt` or `results/paths.txt`, is treated as an "
                          "exact FILE path (parent directories are created as needed). Omit "
                          "-o entirely to only print to the terminal.")
    ap.add_argument("-s", "--scope", default=None,
                     help="scope file OR domain(s) directly, e.g. -s example.com or -s 'example.com,!admin.example.com'. "
                          "Wildcard spellings *.example.com / *example.com / .example.com are all "
                          "equivalent to example.com (domain + subdomains, never a substring match).")
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
                     help="hide the detailed per-target report for targets with no hit; the "
                          "running scanned/remaining/failed progress line always still prints. "
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
          f"{C}Source:{X} {'local files' if a.local else 'remote fetch'}")

    targets_all = list(dict.fromkeys(read_lines(a.input)))
    if not targets_all:
        sys.exit(f"{R}[!] No targets in {a.input}{X}")

    skipped = [t for t in targets_all if get_extension(t) in SKIP_EXTENSIONS]
    targets = [t for t in targets_all if get_extension(t) not in SKIP_EXTENSIONS]
    if skipped:
        print(f"{D}[*] Skipping {len(skipped)} static asset(s) by extension ({', '.join(sorted(SKIP_EXTENSIONS))}){X}")
    if not targets:
        sys.exit(f"{R}[!] Nothing left to scan after extension filtering ({len(skipped)} skipped){X}")

    need_link_discovery = (not a.no_follow) and (not a.local)
    if a.local and not a.no_follow:
        print(f"{D}[*] --local run: skipping JS-link follow-up (no live URLs to fetch).{X}")

    out_kind, out_base, out_file = build_output_paths(a.outdir)
    writer = ResultWriter(out_kind, out_base, out_file, show, run_ts)
    print(f"{C}[*] Save:{X} "
          + (f"{writer.explicit_file}" if writer.kind == "file" else
             (f"{writer.base_dir}/" if writer.kind == "dir" else f"{D}off (console only){X}")))

    t0 = time.time()
    res, scanned, failed, total, discovered_js = run_engine(
        targets, targets_all, skipped, a, inc, exc, show, map_flag, need_link_discovery, writer)
    elapsed = time.time() - t0

    writer.close_streams()
    finalize_main_outputs(writer, res, show, map_flag)

    interesting_all = flag_interesting(res.paths) | flag_interesting(res.urls)

    if writer.enabled:
        aux_dir = writer.base_dir if writer.base_dir else Path(".")

        def out(name):
            return aux_dir / f"{name}-{run_ts}.txt"

        if "all" in modes:
            if skipped:
                save(out("skipped-ext"), skipped)
            if discovered_js:
                save(out("new-js-urls"), sorted(discovered_js))
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
                    "total_js_urls": total, "scanned": scanned, "failed": failed,
                    "elapsed_seconds": round(elapsed, 2),
                    "paths": sorted(res.paths), "urls": sorted(res.urls),
                    "loose_paths": sorted(res.loose_paths),
                    "interesting": sorted(interesting_all), "params": sorted(res.params),
                    "secrets": [{"confidence": c, "type": n, "match": s, "source": src} for c, n, s, src in res.secrets],
                    "sourcemaps": sorted(res.sourcemaps), "sourcemap_sources": smap_sources,
                    "discovered_js": sorted(discovered_js), "errors": res.errors,
                }
                (out("results").with_suffix(".json")).write_text(json.dumps(payload, indent=2))

        print(f"{G}[+] Results written ({run_ts}){X}")
    else:
        print(f"{D}[*] No -o given — nothing written to disk, results shown above only.{X}")

    print(f"\n{G}========== COMPLETE ({elapsed:.1f}s) =========={X}")
    print(f"{C}Total JS URLs :{X} {total}")
    print(f"{C}Scanned       :{X} {scanned}")
    print(f"{R}Failed        :{X} {failed}")
    print(f"{C}Remaining     :{X} {total - scanned}")
    print(f"{C}Followed JS   :{X} {len(discovered_js)}"
          + (f"  {D}({len(skipped)} skipped by ext){X}" if skipped else ""))
    print(f"{G}Unique paths  :{X} {len(res.paths)}  ({D}{len(res.loose_paths)} loose{X})  {Y}({len(flag_interesting(res.paths))} interesting){X}")
    print(f"{M}Unique URLs   :{X} {len(res.urls)}   {Y}({len(flag_interesting(res.urls))} interesting){X}")
    print(f"{O}Candidate secrets:{X} {len(res.secrets)}  {D}(unverified — see confidence labels){X}")
    print(f"{B}Source maps   :{X} {len(res.sourcemaps)}")
    print(f"{W}Param names   :{X} {len(res.params)}")

if __name__ == "__main__":
    main()
