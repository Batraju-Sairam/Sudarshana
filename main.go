// JSRecon v5 (Go port) — concurrent JS reconnaissance for bug bounty workflows.
//
// - Modes (-m/--mode): all, paths, urls, secrets, map — comma-separated, e.g. -m urls,secrets
// - Live output prints strictly in js.txt order, filtered to the chosen mode(s)
// - --silent hides failed/empty targets from the live feed; real hits still show
// - Nothing is written to disk unless -o is given; with -o, every file gets a
//   <category>-<DD-MM-YYYY>-<HHMMSS>.txt name from one shared run timestamp
// - Follows one level of JS-referencing-JS links discovered inside scanned files
//   (respecting --scope if given), and records them in new-js-urls-<ts>.txt
//
// NOTE ON PORTING FROM THE PYTHON VERSION
// Go's regexp package uses RE2, which does not support lookahead/lookbehind
// assertions. Two of the original Python regexes relied on them:
//   - the "loose path" scanner (negative lookbehind + lookahead terminator check)
//   - the "param access" scanner (negative lookahead excluding method calls)
// Both are reproduced here with the same net effect, using a plain regex for
// the matchable core plus manual boundary checks in Go code (see
// findLoosePaths and findParamAccess). Everything else is a direct port.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// ───────────────────────── colors ─────────────────────────

const (
	cC = "\033[1;36m"
	cG = "\033[1;32m"
	cY = "\033[1;33m"
	cB = "\033[1;34m"
	cM = "\033[1;35m"
	cW = "\033[1;37m"
	cR = "\033[1;31m"
	cD = "\033[2;90m"
	cO = "\033[1;91m"
	cX = "\033[0m"
)

// ───────────────────────── startup banner ─────────────────────────

const chakraArt = `
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
`

const titleArt = `
   ████  █   █  ████    ███   ████    ████  █   █   ███   █   █   ███
  █      █   █  █   █  █   █  █   █  █      █   █  █   █  ██  █  █   █
   ███   █   █  █   █  █████  ████    ███   █████  █████  █ █ █  █████
      █  █   █  █   █  █   █  █  █       █  █   █  █   █  █  ██  █   █
  ████    ███   ████   █   █  █   █  ████   █   █  █   █  █   █  █   █
`

func centerString(s string, width int) string {
	// visual width isn't the same as byte length for the box-drawing title,
	// but rune count is a close-enough approximation for centering, matching
	// the intent of Python's str.center().
	n := utf8.RuneCountInString(s)
	if n >= width {
		return s
	}
	total := width - n
	left := total / 2
	right := total - left
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
}

func printBanner() {
	width := 72
	fmt.Println(cC + strings.Repeat("=", width) + cX)
	for _, line := range strings.Split(strings.Trim(chakraArt, "\n"), "\n") {
		fmt.Println(cY + centerString(line, width) + cX)
	}
	fmt.Println()
	for _, line := range strings.Split(strings.Trim(titleArt, "\n"), "\n") {
		fmt.Println(cM + centerString(line, width) + cX)
	}
	fmt.Println(cD + centerString("JS Recon * Bug Bounty Toolkit", width) + cX)
	fmt.Println(cC + strings.Repeat("=", width) + cX)
	fmt.Println()
}

// ───────────────────────── string sets ─────────────────────────

type StrSet map[string]struct{}

func newStrSet() StrSet { return make(StrSet) }

func (s StrSet) Add(v string) { s[v] = struct{}{} }

func (s StrSet) Has(v string) bool { _, ok := s[v]; return ok }

func (s StrSet) Union(o StrSet) StrSet {
	out := newStrSet()
	for k := range s {
		out.Add(k)
	}
	for k := range o {
		out.Add(k)
	}
	return out
}

func (s StrSet) Diff(o StrSet) StrSet {
	out := newStrSet()
	for k := range s {
		if !o.Has(k) {
			out.Add(k)
		}
	}
	return out
}

func (s StrSet) Sorted() []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ───────────────────────── regexes ─────────────────────────

var (
	urlRe = regexp.MustCompile(`(?i)(?:https?:)?//[A-Za-z0-9](?:[A-Za-z0-9\-._~:/?#@!$&*+,;=%]|%[0-9A-Fa-f]{2})*`)

	pathRe = regexp.MustCompile(`(?:"|'|` + "`" + `)(/[^/"'\s` + "`" + `<>()][^"'\s` + "`" + `<>()]*)(?:"|'|` + "`" + `)`)

	badPathRe = regexp.MustCompile(`(?i)^/(?:\*\\?\?|\\\?|\*|\.\.?/)`)

	// LOOSE_PATH_RE core (lookbehind/lookahead re-implemented manually, see findLoosePaths):
	// original: (?<![:/.\w])/(?!/)[A-Za-z][A-Za-z0-9_\-./%]{1,200}(?=[\s"'`<>,;)\]}]|$)
	loosePathCoreRe = regexp.MustCompile(`/[A-Za-z][A-Za-z0-9_\-./%]{1,200}`)

	regexLiteralCtxRe = regexp.MustCompile(`\.(?:replace|match|test|exec|search)\(\s*$`)

	uniEscRe = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	hexEscRe = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

	sourcemapRe = regexp.MustCompile(`//[#@]\s*sourceMappingURL=([^\s*]+)`)

	qparamRe = regexp.MustCompile(`[?&]([a-zA-Z0-9_\[\]\.]{1,40})=`)
	objlitRe = regexp.MustCompile(`(?i)(?:params|query|body|data|payload)\s*[:=]\s*\{([^{}]{0,600})\}`)
	objkeyRe = regexp.MustCompile(`["']?([a-zA-Z_$][a-zA-Z0-9_$]{0,40})["']?\s*:`)

	// PARAM_ACCESS_RE core (negative lookahead re-implemented manually, see findParamAccess):
	// original: \b(?:query|params|body|payload|args)\.([a-zA-Z_$][a-zA-Z0-9_$]{0,40})\b(?!\s*\()
	paramAccessCoreRe = regexp.MustCompile(`\b(?:query|params|body|payload|args)\.([a-zA-Z_$][a-zA-Z0-9_$]{0,40})\b`)
	trailingCallRe    = regexp.MustCompile(`^\s*\(`)

	paramGetRe    = regexp.MustCompile(`(?:params|query|searchParams)\.get\(["']([a-zA-Z0-9_\-.]{1,40})["']\)`)
	formdataRe    = regexp.MustCompile(`(?i)(?:formData|form)\.(?:append|set)\(["']([a-zA-Z0-9_\-.]{1,40})["']`)
	destructureRe = regexp.MustCompile(`\{\s*([^{}]{1,300}?)\s*\}\s*=\s*(?:[\w.]*\.)?(?:query|body|params)\b`)

	interestingRe = regexp.MustCompile(`(?i)(admin|internal|debug|staging|sandbox|backup|\.bak\b|config|swagger|openapi|` +
		`graphql|\.git\b|\.env\b|actuator|console|private|secret|dump|export|migrate|` +
		`impersonat|sudo|superuser|reset[-_]?password|forgot[-_]?password|` +
		`api/v[0-9]+/(?:users?|accounts?|admin)|token|credential|\.sql\b|\.log\b|` +
		`phpinfo|wp-config|\.htpasswd|id_rsa|shell|upload|xxe|ssrf)`)

	ipRe = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)

	schemePrefixRe = regexp.MustCompile(`(?i)^[a-z]+://`)
	splitCommaWSRe = regexp.MustCompile(`[,\s]+`)
)

// Hardcoded — not configurable on the CLI (kept simple on purpose).
var skipExtensions = map[string]struct{}{
	"woff": {}, "css": {}, "png": {}, "svg": {}, "jpg": {}, "woff2": {}, "jpeg": {}, "gif": {},
}

func getExtension(target string) string {
	t := target
	if i := strings.Index(t, "?"); i >= 0 {
		t = t[:i]
	}
	if i := strings.Index(t, "#"); i >= 0 {
		t = t[:i]
	}
	if u, err := url.Parse(t); err == nil && u.Scheme != "" && u.Host != "" {
		t = u.Path
	}
	lastSeg := t
	if i := strings.LastIndex(t, "/"); i >= 0 {
		lastSeg = t[i+1:]
	}
	if i := strings.LastIndex(lastSeg, "."); i >= 0 {
		return strings.ToLower(lastSeg[i+1:])
	}
	return ""
}

type secretDef struct {
	Name    string
	Pattern *regexp.Regexp
	Conf    string
}

var secretPatterns = []secretDef{
	{"AWS Access Key ID", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "high"},
	{"AWS Secret Access Key", regexp.MustCompile(`(?i)aws(?:_|-)?(?:secret)?(?:_|-)?(?:access)?(?:_|-)?key(?:_|-)?(?:id)?["']?\s*[:=]\s*["'][A-Za-z0-9/+=]{40}["']`), "med"},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), "high"},
	{"Google OAuth Token", regexp.MustCompile(`ya29\.[0-9A-Za-z\-_]{20,}`), "high"},
	{"Firebase Server Key", regexp.MustCompile(`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{100,}`), "high"},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,48}`), "high"},
	{"Slack Webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+`), "high"},
	{"Stripe Live Secret Key", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{20,}`), "high"},
	{"Stripe Live Publishable", regexp.MustCompile(`pk_live_[0-9a-zA-Z]{20,}`), "high"},
	{"GitHub Token", regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36,}`), "high"},
	{"GitHub Fine-grained PAT", regexp.MustCompile(`github_pat_[0-9A-Za-z_]{20,}`), "high"},
	{"JWT", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}`), "high"},
	{"Twilio API Key SID", regexp.MustCompile(`SK[0-9a-fA-F]{32}`), "med"},
	{"Twilio Account SID", regexp.MustCompile(`AC[0-9a-fA-F]{32}`), "med"},
	{"Mailgun API Key", regexp.MustCompile(`key-[0-9a-zA-Z]{32}`), "med"},
	{"Mailchimp API Key", regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`), "high"},
	{"Square Access Token", regexp.MustCompile(`sq0(?:atp|csp)-[0-9A-Za-z\-_]{22,43}`), "high"},
	{"Braintree/PayPal Token", regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`), "high"},
	{"Private Key Block", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`), "high"},
	{"Basic Auth in URL", regexp.MustCompile(`https?://[^:/\s"']+:[^@/\s"']+@[^\s"']+`), "high"},
	{"Generic API Key Assign", regexp.MustCompile(`(?i)\b(?:api|app)[_-]?key["']?\s*[:=]\s*["'][0-9A-Za-z\-_]{16,45}["']`), "low"},
	{"Generic Secret Assign", regexp.MustCompile(`(?i)\bsecret["']?\s*[:=]\s*["'][0-9A-Za-z\-_/+=]{16,45}["']`), "low"},
	{"Hardcoded Bearer Token", regexp.MustCompile(`(?i)["']Bearer\s+[A-Za-z0-9\-_.]{20,}["']`), "low"},
}

var paramStopwords = map[string]struct{}{
	"get": {}, "set": {}, "has": {}, "delete": {}, "append": {}, "tostring": {}, "valueof": {},
	"hasownproperty": {}, "keys": {}, "values": {}, "entries": {}, "foreach": {},
	"map": {}, "filter": {}, "reduce": {}, "constructor": {}, "then": {}, "catch": {}, "finally": {}, "length": {},
}

// ───────────────────────── mode handling ─────────────────────────

var validModes = map[string]struct{}{"all": {}, "paths": {}, "urls": {}, "secrets": {}, "map": {}}

func parseModes(raw string) map[string]struct{} {
	tokens := map[string]struct{}{}
	for _, t := range strings.Split(raw, ",") {
		t = strings.ToLower(strings.TrimSpace(t))
		if t != "" {
			tokens[t] = struct{}{}
		}
	}
	var bad []string
	for t := range tokens {
		if _, ok := validModes[t]; !ok {
			bad = append(bad, t)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		var valid []string
		for m := range validModes {
			valid = append(valid, m)
		}
		sort.Strings(valid)
		fmt.Fprintf(os.Stderr, "%s[!] Invalid mode(s): %s. Valid: %s (comma-separate for multiple)%s\n",
			cR, strings.Join(bad, ", "), strings.Join(valid, ", "), cX)
		os.Exit(1)
	}
	if len(tokens) == 0 {
		tokens["all"] = struct{}{}
	}
	return tokens
}

type ShowFlags struct {
	Paths, Urls, Secrets, Params, Sourcemaps bool
}

// resolveShow returns (show flags, map_flag). "map" with nothing else defaults
// to paths+urls+secrets, since map has nothing to attribute otherwise.
func resolveShow(modes map[string]struct{}) (ShowFlags, bool) {
	_, all := modes["all"]
	if all {
		return ShowFlags{Paths: true, Urls: true, Secrets: true, Params: true, Sourcemaps: true}, true
	}
	_, paths := modes["paths"]
	_, urls := modes["urls"]
	_, secrets := modes["secrets"]
	_, mapFlag := modes["map"]
	show := ShowFlags{Paths: paths, Urls: urls, Secrets: secrets, Params: false, Sourcemaps: false}
	if mapFlag && !(show.Paths || show.Urls || show.Secrets) {
		show.Paths, show.Urls, show.Secrets = true, true, true
	}
	return show, mapFlag
}

func sortedModeKeys(modes map[string]struct{}) []string {
	out := make([]string, 0, len(modes))
	for k := range modes {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ───────────────────────── helpers ─────────────────────────

func readLines(f string) []string {
	data, err := os.ReadFile(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[!] File not found: %s%s\n", cR, f, cX)
		os.Exit(1)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func loadScope(s string) (inc, exc []string) {
	if s == "" {
		return nil, nil
	}
	var tokens []string
	if fileExists(s) {
		tokens = readLines(s)
	} else {
		for _, t := range splitCommaWSRe.Split(strings.TrimSpace(s), -1) {
			if t != "" {
				tokens = append(tokens, t)
			}
		}
	}
	incSet, excSet := newStrSet(), newStrSet()
	for _, x := range tokens {
		x = strings.TrimSpace(x)
		if x == "" || strings.HasPrefix(x, "#") {
			continue
		}
		neg := strings.HasPrefix(x, "!")
		if neg {
			x = strings.TrimSpace(x[1:])
		}
		x = schemePrefixRe.ReplaceAllString(x, "")
		if i := strings.Index(x, "/"); i >= 0 {
			x = x[:i]
		}
		if i := strings.Index(x, ":"); i >= 0 {
			x = x[:i]
		}
		x = strings.ToLower(x)
		x = strings.TrimRight(x, ".")
		if strings.HasPrefix(x, "*.") {
			x = x[2:]
		}
		if x != "" {
			if neg {
				excSet.Add(x)
			} else {
				incSet.Add(x)
			}
		}
	}
	return incSet.Sorted(), excSet.Sorted()
}

func inScope(host string, inc, exc []string) bool {
	h := strings.ToLower(strings.TrimRight(host, "."))
	for _, d := range exc {
		if h == d || strings.HasSuffix(h, "."+d) {
			return false
		}
	}
	if len(inc) == 0 {
		return true
	}
	for _, d := range inc {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

func cleanURL(x string) (string, bool) {
	x = html.UnescapeString(x)
	x = strings.TrimSpace(x)
	x = strings.TrimRight(x, ".,;")
	if strings.HasPrefix(x, "//") {
		x = "https:" + x
	}
	u, err := url.Parse(x)
	if err != nil {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Host == "" {
		return "", false
	}
	host := u.Hostname()
	if host != "localhost" && !ipRe.MatchString(host) && !strings.Contains(host, ".") {
		return "", false
	}
	u.Scheme = scheme
	u.Host = strings.ToLower(u.Host)
	if u.Path == "" {
		u.Path = "/"
	}
	u.Fragment = ""
	u.RawFragment = ""
	return u.String(), true
}

func cleanPath(x string) (string, bool) {
	x = html.UnescapeString(x)
	x = strings.TrimSpace(x)
	x = strings.TrimRight(x, ".,;")
	if i := strings.Index(x, "#"); i >= 0 {
		x = x[:i]
	}
	if x == "" || !strings.HasPrefix(x, "/") || strings.HasPrefix(x, "//") || badPathRe.MatchString(x) {
		return "", false
	}
	for _, c := range x {
		if c < 32 {
			return "", false
		}
	}
	return x, true
}

func decodeObfuscation(data string) string {
	d := uniEscRe.ReplaceAllStringFunc(data, func(m string) string {
		sub := uniEscRe.FindStringSubmatch(m)
		n, err := strconv.ParseInt(sub[1], 16, 32)
		if err != nil {
			return m
		}
		return string(rune(n))
	})
	d = hexEscRe.ReplaceAllStringFunc(d, func(m string) string {
		sub := hexEscRe.FindStringSubmatch(m)
		n, err := strconv.ParseInt(sub[1], 16, 32)
		if err != nil {
			return m
		}
		return string(rune(n))
	})
	return d
}

func fetchRemote(target string, timeout time.Duration, retries int, delay float64) (string, string) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	for attempt := 0; attempt <= retries; attempt++ {
		body, code, err := doFetchOnce(client, target, timeout)
		if err == nil && body != "" && (code == "" || strings.HasPrefix(code, "2") || strings.HasPrefix(code, "3")) {
			return body, code
		}
		if attempt == retries {
			return body, code
		}
		sleepFor := delay + rand.Float64()*0.4 + float64(attempt)*0.5
		time.Sleep(time.Duration(sleepFor * float64(time.Second)))
	}
	return "", ""
}

func doFetchOnce(client *http.Client, target string, timeout time.Duration) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 JSRecon/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	buf := &strings.Builder{}
	reader := bufio.NewReader(resp.Body)
	if _, err := reader.WriteTo(buf); err != nil && buf.Len() == 0 {
		return "", strconv.Itoa(resp.StatusCode), err
	}
	return buf.String(), strconv.Itoa(resp.StatusCode), nil
}

func readLocal(path string) (string, string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	return string(data), "200"
}

// looksLikeHTMLDocument filters out soft-200 HTML (homepage/error templates)
// served from a .js path, so it isn't scanned as if it were real JavaScript.
func looksLikeHTMLDocument(data string) bool {
	if data == "" {
		return false
	}
	head := strings.ToLower(strings.TrimLeft(data, "\ufeff \t\r\n"))
	if len(head) > 4096 {
		head = head[:4096]
	}
	if strings.HasPrefix(head, "<!doctype html") || strings.HasPrefix(head, "<html") {
		return true
	}
	if regexp.MustCompile(`(?i)<html(?:\s|>)`).MatchString(head) {
		return true
	}
	if regexp.MustCompile(`(?i)<head(?:\s|>)`).MatchString(head) && regexp.MustCompile(`(?i)<body(?:\s|>)`).MatchString(head) {
		return true
	}
	return false
}

// ───────────────────────── extraction ─────────────────────────

func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

func isLoosePathTerminator(r rune) bool {
	if unicode.IsSpace(r) {
		return true
	}
	return strings.ContainsRune("\"'`<>,;)]}", r)
}

// findLoosePaths re-implements LOOSE_PATH_RE, which in Python relies on a
// negative lookbehind and a lookahead terminator check — neither of which
// RE2 (Go's regexp engine) supports.
func findLoosePaths(text string) []string {
	var out []string
	for _, loc := range loosePathCoreRe.FindAllStringIndex(text, -1) {
		start, end := loc[0], loc[1]

		// exclude if directly inside a regex-literal context, e.g. .replace(
		ctxStart := start - 20
		if ctxStart < 0 {
			ctxStart = 0
		}
		if regexLiteralCtxRe.MatchString(text[ctxStart:start]) {
			continue
		}

		// negative lookbehind: char immediately before match must not be
		// one of : / . or a word character.
		if start > 0 {
			prev, _ := utf8.DecodeLastRuneInString(text[:start])
			if prev == ':' || prev == '/' || prev == '.' || isWordRune(prev) {
				continue
			}
		}

		// lookahead: whatever follows the match must be a terminator char
		// or end-of-string. RE2 already matched greedily, so emulate the
		// backtracking Python's engine would do by trimming from the end.
		matchEnd := end
		for matchEnd-start >= 2 {
			if matchEnd >= len(text) {
				out = append(out, text[start:matchEnd])
				break
			}
			next, _ := utf8.DecodeRuneInString(text[matchEnd:])
			if isLoosePathTerminator(next) {
				out = append(out, text[start:matchEnd])
				break
			}
			_, size := utf8.DecodeLastRuneInString(text[start:matchEnd])
			matchEnd -= size
		}
	}
	return out
}

// findParamAccess re-implements PARAM_ACCESS_RE's trailing negative
// lookahead (?!\s*\() excluding method calls like body.get(...).
func findParamAccess(text string) []string {
	var out []string
	for _, m := range paramAccessCoreRe.FindAllStringSubmatchIndex(text, -1) {
		fullEnd := m[1]
		groupStart, groupEnd := m[2], m[3]
		if trailingCallRe.MatchString(text[fullEnd:]) {
			continue
		}
		out = append(out, text[groupStart:groupEnd])
	}
	return out
}

func extractPathsURLs(data string, inc, exc []string, aggressive bool) (StrSet, StrSet, StrSet) {
	psStrict, us, psLoose := newStrSet(), newStrSet(), newStrSet()
	for _, variant := range []string{data, decodeObfuscation(data)} {
		for _, m := range pathRe.FindAllStringSubmatch(variant, -1) {
			if p, ok := cleanPath(m[1]); ok {
				psStrict.Add(p)
			}
		}
		for _, m := range urlRe.FindAllString(variant, -1) {
			if u, ok := cleanURL(m); ok {
				parsed, err := url.Parse(u)
				if err == nil && inScope(parsed.Hostname(), inc, exc) {
					us.Add(u)
				}
			}
		}
		if aggressive {
			for _, raw := range findLoosePaths(variant) {
				if p, ok := cleanPath(raw); ok && hasAlpha(p) {
					psLoose.Add(p)
				}
			}
		}
	}
	psLoose = psLoose.Diff(psStrict)
	ps := psStrict.Union(psLoose)
	return ps, us, psLoose
}

func hasAlpha(s string) bool {
	for _, c := range s {
		if unicode.IsLetter(c) {
			return true
		}
	}
	return false
}

type SecretHit struct {
	Conf, Name, Snippet, Source string
}

func extractSecrets(data, source string) []SecretHit {
	var hits []SecretHit
	for _, sp := range secretPatterns {
		for _, m := range sp.Pattern.FindAllString(data, -1) {
			snippet := m
			if len(snippet) > 80 {
				snippet = snippet[:77] + "..."
			}
			hits = append(hits, SecretHit{sp.Conf, sp.Name, snippet, source})
		}
	}
	return hits
}

func extractSourcemaps(data, sourceURL string) StrSet {
	out := newStrSet()
	for _, m := range sourcemapRe.FindAllStringSubmatch(data, -1) {
		ref := strings.TrimSpace(m[1])
		if strings.HasPrefix(ref, "data:") {
			continue
		}
		base, err := url.Parse(sourceURL)
		if err != nil {
			continue
		}
		refURL, err := url.Parse(ref)
		if err != nil {
			continue
		}
		out.Add(base.ResolveReference(refURL).String())
	}
	return out
}

func extractParams(data string, ps, us StrSet) StrSet {
	names := newStrSet()
	for target := range ps {
		for _, m := range qparamRe.FindAllStringSubmatch(target, -1) {
			names.Add(m[1])
		}
	}
	for target := range us {
		for _, m := range qparamRe.FindAllStringSubmatch(target, -1) {
			names.Add(m[1])
		}
	}
	for _, m := range qparamRe.FindAllStringSubmatch(data, -1) {
		names.Add(m[1])
	}
	for _, blk := range objlitRe.FindAllStringSubmatch(data, -1) {
		for _, km := range objkeyRe.FindAllStringSubmatch(blk[1], -1) {
			names.Add(km[1])
		}
	}
	for _, tok := range findParamAccess(data) {
		if _, bad := paramStopwords[strings.ToLower(tok)]; !bad {
			names.Add(tok)
		}
	}
	for _, m := range paramGetRe.FindAllStringSubmatch(data, -1) {
		names.Add(m[1])
	}
	for _, m := range formdataRe.FindAllStringSubmatch(data, -1) {
		names.Add(m[1])
	}
	for _, blk := range destructureRe.FindAllStringSubmatch(data, -1) {
		for _, tok := range strings.Split(blk[1], ",") {
			tok = strings.TrimSpace(tok)
			if i := strings.Index(tok, ":"); i >= 0 {
				tok = tok[:i]
			}
			if i := strings.Index(tok, "="); i >= 0 {
				tok = tok[:i]
			}
			tok = strings.TrimSpace(tok)
			if regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`).MatchString(tok) {
				names.Add(tok)
			}
		}
	}
	delete(names, "")
	return names
}

func flagInteresting(items StrSet) StrSet {
	out := newStrSet()
	for x := range items {
		if interestingRe.MatchString(x) {
			out.Add(x)
		}
	}
	return out
}

// ───────────────────────── live categorized output ─────────────────────────

func printTargetReport(src string, ok bool, ps, us, psLoose StrSet, secrets []SecretHit, smaps, params, interesting StrSet, show ShowFlags) {
	status := cG + "OK" + cX
	if !ok {
		status = cR + "FAIL" + cX
	}
	fmt.Printf("\n%s==>%s [%s] %s\n", cC, cX, status, src)
	if !ok {
		return
	}
	shownAnything := false
	if show.Urls && len(us) > 0 {
		shownAnything = true
		fmt.Printf("%s  URLS (%d):%s\n", cM, len(us), cX)
		for _, u := range us.Sorted() {
			tag := ""
			if interesting.Has(u) {
				tag = fmt.Sprintf(" %s[interesting]%s", cY, cX)
			}
			fmt.Printf("    %s%s\n", u, tag)
		}
	}
	if show.Paths {
		corePaths := ps.Diff(psLoose)
		if len(corePaths) > 0 {
			shownAnything = true
			fmt.Printf("%s  PATHS (%d):%s\n", cB, len(corePaths), cX)
			for _, p := range corePaths.Sorted() {
				tag := ""
				if interesting.Has(p) {
					tag = fmt.Sprintf(" %s[interesting]%s", cY, cX)
				}
				fmt.Printf("    %s%s\n", p, tag)
			}
		}
		if len(psLoose) > 0 {
			shownAnything = true
			fmt.Printf("%s  PATHS — loose/unverified (%d):%s\n", cD, len(psLoose), cX)
			for _, p := range psLoose.Sorted() {
				fmt.Printf("    %s\n", p)
			}
		}
	}
	if show.Secrets && len(secrets) > 0 {
		shownAnything = true
		fmt.Printf("%s  SECRETS (%d) — candidates only, verify before reporting:%s\n", cO, len(secrets), cX)
		for _, h := range secrets {
			fmt.Printf("    [%s] %s: %s\n", strings.ToUpper(h.Conf), h.Name, h.Snippet)
		}
	}
	if show.Params && len(params) > 0 {
		shownAnything = true
		fmt.Printf("%s  PARAMS (%d):%s %s\n", cW, len(params), cX, strings.Join(params.Sorted(), ", "))
	}
	if show.Sourcemaps && len(smaps) > 0 {
		shownAnything = true
		fmt.Printf("%s  SOURCEMAPS (%d):%s\n", cG, len(smaps), cX)
		for _, sm := range smaps.Sorted() {
			fmt.Printf("    %s\n", sm)
		}
	}
	if !shownAnything {
		fmt.Printf("  %s(nothing found)%s\n", cD, cX)
	}
}

// ───────────────────────── scan orchestration ─────────────────────────

type PathSrc struct{ Item, Src string }

type Results struct {
	Paths, Urls, LoosePaths StrSet
	Secrets                 []SecretHit
	Sourcemaps, Params      StrSet
	Mapping, URLMapping     []PathSrc
	Done                    int
	Errors                  []string
}

func newResults() *Results {
	return &Results{
		Paths: newStrSet(), Urls: newStrSet(), LoosePaths: newStrSet(),
		Sourcemaps: newStrSet(), Params: newStrSet(),
	}
}

type ScanItem struct {
	Src         string
	Body        string
	Code        string
	Paths       StrSet
	Urls        StrSet
	LoosePaths  StrSet
	Sourcemaps  StrSet
	Params      StrSet
	Secrets     []SecretHit
	Interesting StrSet
}

type Args struct {
	Mode              string
	Input             string
	Outdir            string
	Scope             string
	Timeout           int
	Threads           int
	Delay             float64
	Retries           int
	Local             bool
	Aggressive        bool
	NoSecrets         bool
	NoSourcemap       bool
	ResolveSourcemaps bool
	JSONOut           bool
	Diff              string
	NoFollow          bool
	Silent            bool
}

func scanOne(src string, args Args, inc, exc []string) ScanItem {
	var body, code string
	if args.Local {
		body, code = readLocal(src)
	} else {
		body, code = fetchRemote(src, time.Duration(args.Timeout)*time.Second, args.Retries, args.Delay)
	}
	if body != "" && looksLikeHTMLDocument(body) {
		body = ""
	}
	ps, us, psLoose := newStrSet(), newStrSet(), newStrSet()
	smaps, params := newStrSet(), newStrSet()
	var secrets []SecretHit
	if body != "" {
		ps, us, psLoose = extractPathsURLs(body, inc, exc, args.Aggressive)
		if !args.NoSecrets {
			secrets = extractSecrets(body, src)
		}
		if !args.NoSourcemap {
			smaps = extractSourcemaps(body, src)
		}
		params = extractParams(body, ps, us)
	}
	interesting := flagInteresting(ps).Union(flagInteresting(us))
	return ScanItem{
		Src: src, Body: body, Code: code, Paths: ps, Urls: us, LoosePaths: psLoose,
		Sourcemaps: smaps, Params: params, Secrets: secrets, Interesting: interesting,
	}
}

func mergeResult(res *Results, item ScanItem) {
	res.Paths = res.Paths.Union(item.Paths)
	res.Urls = res.Urls.Union(item.Urls)
	res.LoosePaths = res.LoosePaths.Union(item.LoosePaths)
	res.Secrets = append(res.Secrets, item.Secrets...)
	res.Sourcemaps = res.Sourcemaps.Union(item.Sourcemaps)
	res.Params = res.Params.Union(item.Params)
	for p := range item.Paths {
		res.Mapping = append(res.Mapping, PathSrc{p, item.Src})
	}
	for u := range item.Urls {
		res.URLMapping = append(res.URLMapping, PathSrc{u, item.Src})
	}
	res.Done++
	if item.Body == "" {
		res.Errors = append(res.Errors, item.Src)
	}
}

func hasHit(item ScanItem, show ShowFlags) bool {
	return (show.Paths && len(item.Paths) > 0) ||
		(show.Urls && len(item.Urls) > 0) ||
		(show.Secrets && len(item.Secrets) > 0) ||
		(show.Params && len(item.Params) > 0) ||
		(show.Sourcemaps && len(item.Sourcemaps) > 0)
}

// scan fetches concurrently but PRINTS strictly in input order so [n/total]
// always matches the target's position in the list being scanned.
func scan(targets []string, args Args, inc, exc []string, show ShowFlags, res *Results, label string) *Results {
	if res == nil {
		res = newResults()
	}
	total := len(targets)
	channels := make([]chan ScanItem, total)
	sem := make(chan struct{}, args.Threads)
	var wg sync.WaitGroup
	for i, t := range targets {
		channels[i] = make(chan ScanItem, 1)
		wg.Add(1)
		go func(i int, t string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			channels[i] <- scanOne(t, args, inc, exc)
		}(i, t)
	}
	for idx := 0; idx < total; idx++ {
		item := <-channels[idx]
		mergeResult(res, item)
		found := hasHit(item, show)
		if args.Silent && !found {
			continue
		}
		fmt.Printf("%s%s[%d/%d]%s", cD, label, idx+1, total, cX)
		printTargetReport(item.Src, item.Body != "", item.Paths, item.Urls, item.LoosePaths,
			item.Secrets, item.Sourcemaps, item.Params, item.Interesting, show)
	}
	wg.Wait()
	return res
}

// ───────────────────────── source-map follow-up ─────────────────────────

func resolveSourcemapSources(smapURLs StrSet, args Args, inc, exc []string) map[string][]string {
	found := map[string][]string{}
	for _, u := range smapURLs.Sorted() {
		parsed, err := url.Parse(u)
		if err != nil || !inScope(parsed.Hostname(), inc, exc) {
			continue
		}
		body, _ := fetchRemote(u, time.Duration(args.Timeout)*time.Second, 1, args.Delay)
		if body == "" {
			continue
		}
		var j map[string]interface{}
		if err := json.Unmarshal([]byte(body), &j); err != nil {
			continue
		}
		if rawSrcs, ok := j["sources"].([]interface{}); ok && len(rawSrcs) > 0 {
			var srcs []string
			for _, s := range rawSrcs {
				if str, ok := s.(string); ok {
					srcs = append(srcs, str)
				}
			}
			if len(srcs) > 0 {
				found[u] = srcs
			}
		}
	}
	return found
}

// ───────────────────────── diff mode ─────────────────────────

func doDiff(baselineFile string, current StrSet) []string {
	old := newStrSet()
	if fileExists(baselineFile) {
		for _, l := range readLines(baselineFile) {
			old.Add(l)
		}
	}
	return current.Diff(old).Sorted()
}

// ───────────────────────── output ─────────────────────────

func save(path string, lines []string) {
	content := ""
	if len(lines) > 0 {
		content = strings.Join(lines, "\n") + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "%s[!] Failed to write %s: %v%s\n", cR, path, err, cX)
	}
}

func formatSecrets(secrets []SecretHit) []string {
	type group struct {
		label, conf string
	}
	groups := []group{
		{"HIGH — tight format, low false-positive rate", "high"},
		{"MEDIUM — structured but has legitimate lookalikes", "med"},
		{"LOW — generic shape, expect noise, verify by hand", "low"},
	}
	var out []string
	for _, g := range groups {
		var rows []SecretHit
		for _, s := range secrets {
			if s.Conf == g.conf {
				rows = append(rows, s)
			}
		}
		if len(rows) == 0 {
			continue
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
		out = append(out, fmt.Sprintf("# %s (%d)", g.label, len(rows)))
		for _, r := range rows {
			out = append(out, fmt.Sprintf("%s: %s  (source: %s)", r.Name, r.Snippet, r.Source))
		}
		out = append(out, "")
	}
	return out
}

// ───────────────────────── main ─────────────────────────

func main() {
	rand.Seed(time.Now().UnixNano())
	printBanner()

	var a Args
	fs := flag.NewFlagSet("jsrecon", flag.ExitOnError)
	fs.StringVar(&a.Mode, "m", "all", "comma-separated: all,paths,urls,secrets,map")
	fs.StringVar(&a.Mode, "mode", "all", "comma-separated: all,paths,urls,secrets,map — e.g. -mode urls,secrets")
	fs.StringVar(&a.Input, "i", "js.txt", "file of JS URLs (or local paths with --local), one per line")
	fs.StringVar(&a.Input, "input", "js.txt", "file of JS URLs (or local paths with --local), one per line")
	fs.StringVar(&a.Outdir, "o", "", "directory to persist results into. Omit to only print to the terminal.")
	fs.StringVar(&a.Outdir, "outdir", "", "directory to persist results into. Omit to only print to the terminal.")
	fs.StringVar(&a.Scope, "s", "", "scope file OR domain(s) directly, e.g. -s example.com or -s 'example.com,!admin.example.com'")
	fs.StringVar(&a.Scope, "scope", "", "scope file OR domain(s) directly")
	fs.IntVar(&a.Timeout, "t", 20, "fetch timeout in seconds")
	fs.IntVar(&a.Timeout, "timeout", 20, "fetch timeout in seconds")
	fs.IntVar(&a.Threads, "c", 4, "concurrent fetch workers (default 4)")
	fs.IntVar(&a.Threads, "threads", 4, "concurrent fetch workers (default 4)")
	fs.Float64Var(&a.Delay, "delay", 0.0, "base delay before a retry, per worker")
	fs.IntVar(&a.Retries, "retries", 2, "retry count per target")
	fs.BoolVar(&a.Local, "local", false, "treat --input lines as local file paths, not URLs")
	fs.BoolVar(&a.Aggressive, "aggressive", false, "also catch unquoted/loosely-delimited paths. Higher false-positive rate.")
	fs.BoolVar(&a.NoSecrets, "no-secrets", false, "disable secret scanning")
	fs.BoolVar(&a.NoSourcemap, "no-sourcemap", false, "disable sourcemap discovery")
	fs.BoolVar(&a.ResolveSourcemaps, "resolve-sourcemaps", false, "fetch discovered .map files and list original source paths")
	fs.BoolVar(&a.JSONOut, "json", false, "also write results.json (requires -o)")
	fs.StringVar(&a.Diff, "diff", "", "compare against a previous run's saved list (requires -o); pass BASELINE file")
	fs.BoolVar(&a.NoFollow, "no-follow", false, "don't auto-scan .js URLs discovered inside scanned JS files")
	fs.BoolVar(&a.Silent, "silent", false, "hide failed/empty targets from live output; real hits still show, in js.txt order")
	fs.Parse(os.Args[1:])

	modes := parseModes(a.Mode)
	show, mapFlag := resolveShow(modes)
	inc, exc := loadScope(a.Scope)
	runTs := time.Now().Format("02-01-2006-150405")

	mapNote := ""
	if mapFlag {
		mapNote = fmt.Sprintf("  %s(map: on)%s", cD, cX)
	}
	fmt.Printf("%s[*] Mode:%s %s%s\n", cC, cX, strings.Join(sortedModeKeys(modes), ","), mapNote)

	scopeDesc := "OFF — all discovered URLs"
	if a.Scope != "" {
		scopeDesc = a.Scope
	}
	scopeNote := ""
	if a.Scope != "" {
		exclDesc := ""
		if len(exc) > 0 {
			exclDesc = " | excl: " + strings.Join(exc, ", ")
		}
		incDesc := strings.Join(inc, ", ")
		if incDesc == "" {
			incDesc = "-"
		}
		scopeNote = fmt.Sprintf("  %s(parsed as: %s%s)%s", cD, incDesc, exclDesc, cX)
	}
	fmt.Printf("%s[*] Scope:%s %s%s\n", cC, cX, scopeDesc, scopeNote)

	source := "remote fetch"
	if a.Local {
		source = "local files"
	}
	saveDesc := a.Outdir
	if saveDesc == "" {
		saveDesc = cD + "off (console only)" + cX
	}
	fmt.Printf("%s[*] Threads:%s %d  %sRetries:%s %d  %sSource:%s %s  %sSave:%s %s\n",
		cC, cX, a.Threads, cC, cX, a.Retries, cC, cX, source, cC, cX, saveDesc)

	targetsAllRaw := readLines(a.Input)
	seen := newStrSet()
	var targetsAll []string
	for _, t := range targetsAllRaw {
		if !seen.Has(t) {
			seen.Add(t)
			targetsAll = append(targetsAll, t)
		}
	}
	if len(targetsAll) == 0 {
		fmt.Fprintf(os.Stderr, "%s[!] No targets in %s%s\n", cR, a.Input, cX)
		os.Exit(1)
	}

	var skipped, targets []string
	for _, t := range targetsAll {
		if _, bad := skipExtensions[getExtension(t)]; bad {
			skipped = append(skipped, t)
		} else {
			targets = append(targets, t)
		}
	}
	if len(skipped) > 0 {
		var exts []string
		for e := range skipExtensions {
			exts = append(exts, e)
		}
		sort.Strings(exts)
		fmt.Printf("%s[*] Skipping %d static asset(s) by extension (%s)%s\n", cD, len(skipped), strings.Join(exts, ", "), cX)
	}
	if len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "%s[!] Nothing left to scan after extension filtering (%d skipped)%s\n", cR, len(skipped), cX)
		os.Exit(1)
	}

	t0 := time.Now()
	res := scan(targets, a, inc, exc, show, nil, "")

	// follow one level of JS-referencing-JS links
	known := newStrSet()
	for _, t := range targetsAll {
		known.Add(t)
	}
	for _, t := range skipped {
		known.Add(t)
	}
	discoveredJS := newStrSet()
	if !a.NoFollow && !a.Local {
		for u := range res.Urls {
			if getExtension(u) == "js" && !known.Has(u) {
				discoveredJS.Add(u)
			}
		}
		for _, ps := range res.Mapping {
			if getExtension(ps.Item) == "js" {
				if base, err := url.Parse(ps.Src); err == nil {
					if rel, err2 := url.Parse(ps.Item); err2 == nil {
						full := base.ResolveReference(rel).String()
						if !known.Has(full) {
							discoveredJS.Add(full)
						}
					}
				}
			}
		}
		filtered := newStrSet()
		for u := range discoveredJS {
			if parsed, err := url.Parse(u); err == nil && inScope(parsed.Hostname(), inc, exc) {
				filtered.Add(u)
			}
		}
		discoveredJS = filtered
	} else if a.Local && !a.NoFollow {
		fmt.Printf("%s[*] --local run: skipping JS-link follow-up (no live URLs to fetch).%s\n", cD, cX)
	}

	if len(discoveredJS) > 0 {
		fmt.Printf("\n%s[*] Following %d newly discovered JS link(s)...%s\n", cY, len(discoveredJS), cX)
		res = scan(discoveredJS.Sorted(), a, inc, exc, show, res, "[new] ")
	}

	elapsed := time.Since(t0).Seconds()
	interestingAll := flagInteresting(res.Paths).Union(flagInteresting(res.Urls))

	_, allMode := modes["all"]

	if a.Outdir != "" {
		if err := os.MkdirAll(a.Outdir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "%s[!] Failed to create outdir: %v%s\n", cR, err, cX)
			os.Exit(1)
		}
		out := func(name string) string {
			return filepath.Join(a.Outdir, fmt.Sprintf("%s-%s.txt", name, runTs))
		}

		if len(skipped) > 0 {
			save(out("skipped-ext"), skipped)
		}
		if len(discoveredJS) > 0 {
			save(out("new-js-urls"), discoveredJS.Sorted())
		}

		if show.Paths {
			if mapFlag {
				lines := newStrSet()
				for _, ps := range res.Mapping {
					lines.Add(fmt.Sprintf("%s\t%s", ps.Item, ps.Src))
				}
				save(out("paths"), lines.Sorted())
			} else {
				save(out("paths"), res.Paths.Sorted())
			}
		}
		if show.Urls {
			if mapFlag {
				lines := newStrSet()
				for _, us := range res.URLMapping {
					lines.Add(fmt.Sprintf("%s\t%s", us.Item, us.Src))
				}
				save(out("urls"), lines.Sorted())
			} else {
				save(out("urls"), res.Urls.Sorted())
			}
		}
		if show.Secrets {
			save(out("secrets"), formatSecrets(res.Secrets))
		}
		if show.Params {
			save(out("params"), res.Params.Sorted())
		}
		if show.Sourcemaps {
			save(out("sourcemaps"), res.Sourcemaps.Sorted())
		}
		if allMode {
			save(out("interesting"), interestingAll.Sorted())
			if len(res.Errors) > 0 {
				save(out("errors"), res.Errors)
			}
			if a.Aggressive {
				save(out("paths-loose"), res.LoosePaths.Sorted())
			}
			smapSources := map[string][]string{}
			if a.ResolveSourcemaps && len(res.Sourcemaps) > 0 {
				fmt.Printf("%s[*] Resolving %d source map(s)...%s\n", cY, len(res.Sourcemaps), cX)
				smapSources = resolveSourcemapSources(res.Sourcemaps, a, inc, exc)
				var lines []string
				smapKeys := make([]string, 0, len(smapSources))
				for k := range smapSources {
					smapKeys = append(smapKeys, k)
				}
				sort.Strings(smapKeys)
				for _, u := range smapKeys {
					lines = append(lines, "# "+u)
					lines = append(lines, smapSources[u]...)
				}
				save(out("sourcemap-sources"), lines)
			}
			if a.Diff != "" {
				save(out("new-findings"), doDiff(a.Diff, res.Paths.Union(res.Urls)))
			}
			if a.JSONOut {
				secretsJSON := make([]map[string]string, 0, len(res.Secrets))
				for _, s := range res.Secrets {
					secretsJSON = append(secretsJSON, map[string]string{
						"confidence": s.Conf, "type": s.Name, "match": s.Snippet, "source": s.Source,
					})
				}
				payload := map[string]interface{}{
					"scanned": len(targets), "elapsed_seconds": roundTo(elapsed, 2),
					"paths": res.Paths.Sorted(), "urls": res.Urls.Sorted(),
					"loose_paths":       res.LoosePaths.Sorted(),
					"interesting":       interestingAll.Sorted(),
					"params":            res.Params.Sorted(),
					"secrets":           secretsJSON,
					"sourcemaps":        res.Sourcemaps.Sorted(),
					"sourcemap_sources": smapSources,
					"discovered_js":     discoveredJS.Sorted(),
					"errors":            res.Errors,
				}
				data, err := json.MarshalIndent(payload, "", "  ")
				if err == nil {
					jsonPath := strings.TrimSuffix(out("results"), ".txt") + ".json"
					if err := os.WriteFile(jsonPath, data, 0644); err != nil {
						fmt.Fprintf(os.Stderr, "%s[!] Failed to write %s: %v%s\n", cR, jsonPath, err, cX)
					}
				}
			}
		}
		fmt.Printf("%s[+] Results written to %s/ (timestamp %s)%s\n", cG, a.Outdir, runTs, cX)
	} else {
		fmt.Printf("%s[*] No -o given — nothing written to disk, results shown above only.%s\n", cD, cX)
	}

	fmt.Printf("\n%s========== COMPLETE (%.1fs) ==========%s\n", cG, elapsed, cX)
	followedNote := ""
	if len(skipped) > 0 || len(discoveredJS) > 0 {
		followedNote = fmt.Sprintf("  %s(%d skipped by ext, %d followed)%s", cD, len(skipped), len(discoveredJS), cX)
	}
	fmt.Printf("%sJS files scanned :%s %d  (%s%d failed%s)%s\n", cC, cX, res.Done, cR, len(res.Errors), cX, followedNote)
	fmt.Printf("%sUnique paths     :%s %d  (%s%d loose%s)  %s(%d interesting)%s\n",
		cG, cX, len(res.Paths), cD, len(res.LoosePaths), cX, cY, len(flagInteresting(res.Paths)), cX)
	fmt.Printf("%sUnique URLs      :%s %d   %s(%d interesting)%s\n",
		cM, cX, len(res.Urls), cY, len(flagInteresting(res.Urls)), cX)
	fmt.Printf("%sCandidate secrets:%s %d  %s(unverified — see confidence labels)%s\n",
		cO, cX, len(res.Secrets), cD, cX)
	fmt.Printf("%sSource maps      :%s %d\n", cB, cX, len(res.Sourcemaps))
	fmt.Printf("%sParam names      :%s %d\n", cW, cX, len(res.Params))
}

func roundTo(f float64, places int) float64 {
	shift := 1.0
	for i := 0; i < places; i++ {
		shift *= 10
	}
	return float64(int(f*shift+0.5)) / shift
}
