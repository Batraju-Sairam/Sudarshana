# JSRecon (Go port)

A straight port of your Python `jsrecon.py` to a single-binary Go CLI, so you
can ship it as:

```
go install github.com/Batraju-Sairam/Sudarshana@latest
```

## Before you push this

**I could not compile or run this in the sandbox** — there's no Go toolchain
installed and no network access to fetch one, so this hasn't been built or
tested. I did a careful manual pass (imports, types, regex syntax, brace/paren
matching) and it should build cleanly, but please run `go build ./...` and
smoke-test it against a real `js.txt` before you rely on it or publish it.
Send me the compiler output if anything doesn't line up and I'll fix it.

## What changed vs. the Python version (unavoidable, not stylistic)

Everything is a direct 1:1 port of your logic — same flags, same modes, same
output file naming/timestamp format, same "one level of JS-referencing-JS"
follow-up, same secret pattern list, same skip-extensions set. The one thing
that couldn't be ported byte-for-byte:

**Go's `regexp` package uses RE2, which has no lookahead/lookbehind support.**
Two of your original regexes depend on it:

- `LOOSE_PATH_RE` — used a negative lookbehind (`(?<![:/.\w])`) and a
  lookahead terminator check (`(?=[\s"'`+"`"+`<>,;)\]}]|$)`).
- `PARAM_ACCESS_RE` — used a negative lookahead (`(?!\s*\()`) to exclude
  method calls like `body.get(...)`.

Both are reproduced with the same net effect in `findLoosePaths` and
`findParamAccess` in `main.go`: a plain RE2 regex finds the matchable core,
then a small amount of Go code checks the same boundary conditions (previous
character, following character, trailing `(`) that the Python lookaround did.
Behavior should match on real-world input; it's called out in comments in the
code (search for "RE2") in case you ever want to audit it against the
original.

Also swapped `curl` subprocess calls for Go's native `net/http` (with TLS
verification disabled and redirects followed, matching your `curl -skL`), so
the binary has zero external dependencies — that's what makes `go install`
possible in the first place.

## Build & install

```bash
cd jsrecon
go build -o jsrecon .          # local binary
# or, once pushed to GitHub:
go install github.com/YOUR_USERNAME/jsrecon@latest
```

Replace `YOUR_USERNAME` in `go.mod` and the module path before pushing.

## Usage

Identical to the Python version:

```bash
jsrecon -i js.txt -m urls,secrets -o out/ -s example.com --aggressive
```

Run `sudarshana --help` (or `-h`) for the full flag list — flags work with
either one or two dashes (`-silent` and `--silent` both work, so there's no
need for the dual-registration hack the Python argparse version used).
