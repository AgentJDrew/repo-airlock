# repo-airlock

[![CI](https://github.com/AgentJDrew/repo-airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/AgentJDrew/repo-airlock/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/repo-airlock.svg)](https://pypi.org/project/repo-airlock/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Zero dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](pyproject.toml)

**About to open-source a private repo? Run it through the airlock first.**

`repo-airlock` is a pre-publication scanner: point it at a directory and it tells you, in
plain language, whether it's safe to make public — and if not, exactly what to fix and where.

It's not a secret-scanning engine competing with gitleaks or trufflehog. It's the **checklist you
run right before you flip a repo from private to public** — secrets, yes, but also the privacy and
hygiene issues that pure secret scanners don't look for at all: your home directory leaking your
OS username, your internal hostnames, your LAN's IP range, a missing LICENSE, a `node_modules/`
you forgot to `.gitignore`.

```
airlock scan . --history
```

One command. Zero dependencies. A verdict you can act on.

## Quickstart

```bash
pip install repo-airlock
airlock scan .
```

Or run it without installing anything, straight from a checkout:

```bash
git clone https://github.com/AgentJDrew/repo-airlock
cd repo-airlock
pip install -e .
airlock scan /path/to/the-repo-youre-about-to-publish --history
```

## Sample report

```
$ airlock scan . 
repo-airlock scan report
========================================

[HIGH] (2)
  .env:0  file name '.env' matches a known credential-file pattern — .env
  config.py:1  AWS access key ID found — AKIA...MPLE

[MEDIUM] (4)
  .:0  no LICENSE file found — repo has no explicit open-source license
  .:0  no README file found
  notes.txt:2  absolute Windows user path leaks local username — C:\U...jdoe
  notes.txt:2  private IP address found (RFC1918 private IP (10.0.0.0/8)) — 10.0...5.12

[LOW] (3)
  .:0  no .gitignore found — increases risk of accidentally committing junk/secrets
  notes.txt:1  email address found — jane....com
  notes.txt:1  phone-number-shaped string found — 555-...3948

----------------------------------------
Scanned 3 file(s). Findings: HIGH=2 MEDIUM=4 LOW=3

VERDICT: HOLD
```

Every match is redacted — you get `AKIA...MPLE`, never the real key, even in your own terminal
scrollback or CI logs. The verdict is either `CLEARED` or `HOLD`, and the exit code follows it, so
this drops straight into a pre-publish checklist or a CI gate.

## Detectors

| Detector | What it catches | Default severity |
|---|---|---|
| Known secret tokens | AWS keys, GitHub tokens (`ghp_`/`gho_`/`github_pat_`), Slack tokens/webhooks, Stripe live keys, Google API keys, JWTs, PEM private key blocks | HIGH |
| Generic credential assignment | `password = "..."`, `api_key: '...'` — hardcoded values regex can't name | MEDIUM |
| High-entropy string literal | Long, random-looking string literals — a safety net for token formats not otherwise recognized | LOW |
| Credential files | `.env*`, `*.pem`, `*.pfx`, `id_rsa*`, `.netrc`, `credentials`, and JSON files containing a `private_key` field (cloud service-account keys) | HIGH |
| Email addresses | Real-looking email addresses (allowlists `example.com`, GitHub noreply, etc.) | LOW |
| Phone numbers | US-style phone number patterns | LOW |
| Local user paths | `C:\Users\<name>`, `/Users/<name>`, `/home/<name>` — leaks the machine owner's username | MEDIUM |
| Internal hostnames | `*.internal`, `*.corp`, `*.local`, `*.lan`, `*.intranet` | LOW |
| Private / CGNAT IPs | RFC1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) **and** the Tailscale/carrier-NAT CGNAT range (`100.64.0.0/10`) | MEDIUM |
| Git history (`--history`) | Runs every detector above against `git log -p --all` so a secret **removed in a later commit** is still flagged — deleting the file today doesn't purge it from history | same as source detector |
| Publication hygiene | Missing LICENSE, missing/stub README, missing `.gitignore`, tracked `node_modules`/`venv`/`dist`/`build`, tracked binaries over 5MB | LOW–MEDIUM |

## Why not just gitleaks / trufflehog?

Use them too — they're excellent at deep secret detection (verified detection against live APIs,
huge rule sets, entropy tuning refined over years). `repo-airlock` is not trying to out-detect them
on secrets specifically. It's solving a different, narrower problem: **"is this repo ready to go
from private to public," which is a bigger question than "does it contain a secret."**

| | gitleaks / trufflehog | repo-airlock |
|---|---|---|
| Secret detection depth | Extensive, verified, actively maintained rule sets | Solid coverage of the common cases + entropy net |
| Privacy/identity leaks (usernames in paths, internal hostnames, private IPs) | No | Yes |
| Publication hygiene (LICENSE, README, tracked build output) | No | Yes |
| History-aware, in plain English ("still in history, here's how to fix it") | Findings only | Findings + explicit remediation guidance |
| Setup | Binary install / Docker | `pip install`, zero dependencies |
| Verdict for a go/no-go decision | You interpret the findings | Explicit `CLEARED` / `HOLD` + CI exit code |

If you want maximum secret-detection recall, run gitleaks/trufflehog as your deep scanner and
`repo-airlock` as the final pre-publish gate that checks the things they don't. They compose well
together — nothing here conflicts with running both.

## CLI reference

```
airlock scan <path> [options]

  --history              also scan full git history (git log -p --all)
  --format {console,md,json}   output format (default: console)
  --fail-on {low,medium,high}  minimum severity that causes exit code 1 (default: high)
  --baseline <file>      suppress findings acknowledged in a baseline JSON file
  --write-baseline <file>  write current findings as a new baseline instead of failing
  --no-color             disable ANSI color in console output
```

Exit code is `0` when the verdict is `CLEARED` at the chosen `--fail-on` threshold, and `1`
otherwise — safe to use directly in a CI job's pass/fail signal.

### Baseline (acknowledge a false positive)

```bash
# Review the findings, then bless the ones that are false positives / accepted risk:
airlock scan . --write-baseline .airlock-baseline.json

# Future scans suppress anything in the baseline, but still catch anything new:
airlock scan . --baseline .airlock-baseline.json
```

## CI usage

```yaml
# .github/workflows/airlock.yml
name: repo-airlock
on: [push, pull_request]
jobs:
  airlock:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history, needed for --history
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install repo-airlock
      - run: airlock scan . --history --fail-on high --baseline .airlock-baseline.json
```

## Engineering notes

- **Zero runtime dependencies.** The entire tool is Python standard library — `re`, `ipaddress`,
  `json`, `argparse`, `subprocess` (for git). Nothing to audit in your supply chain, nothing to pin.
- **src layout**, typed, tested. `pytest` covers every detector individually plus integration tests
  for the scanner, CLI, baseline suppression, and git history scanning — including a self-scan test
  that runs `repo-airlock` against its own source tree.
- **What gets scanned** mirrors "what would actually go public": inside a git repo, that's tracked
  files plus untracked-but-not-`.gitignore`d files (so new work you haven't committed yet is still
  checked). Outside a git repo, it's a plain filesystem walk that still skips common dependency
  directories (`.venv`, `node_modules`, etc.) so you're not drowned in third-party false positives.
- **Redaction is non-negotiable.** Every finding shows `first4...last4` of a match, never the full
  value — in console output, Markdown, and JSON alike.
- **Hardened against hostile input.** The scanner reads arbitrary, untrusted file content and
  `git log -p` output, so it's an attack surface itself. Every detector regex uses bounded
  quantifiers (no catastrophic backtracking), each line is length-capped before it reaches the
  regex engine, whole-file size is capped, binary/non-UTF-8 files are skipped, and the git
  subprocesses use fixed argument lists (never a shell) with timeouts — so a crafted or malicious
  repo can't hang, OOM, or inject a command.

## Testing / fake fixtures

The test suite has to feed the detectors things that *look* like secrets so it can prove they fire.
That creates a subtle problem: some provider token formats (Slack `xoxb-` tokens and webhook URLs,
Stripe `sk_live_`/`sk_test_` keys, Google `AIza...` keys) are realistic enough that **GitHub's own
secret scanner reacts to them as a contiguous string literal in a committed file — even when the
value is obviously fake.** Slack/Stripe get rejected outright by push protection; a fake Google key
sails through the push but then trips a post-push secret-scanning alert.

So those particular test values are **assembled at runtime from fragments** (e.g.
`"sk_" + "live_" + ...`, `"AIza..." + "..." + "..."`) in `tests/test_secrets_detector.py`, and are
deliberately absent as literals from `tests/fixtures/fake_secrets.txt`. No contiguous
scanner-matching token is ever committed, yet the assembled values still match repo-airlock's
regexes, so the assertions remain a real test. Values GitHub does *not* flag — the public AWS docs
example key `AKIAIOSFODNN7EXAMPLE`, `ghp_` tokens, JWTs, PEM blocks — are left as plain literals for
readability.

Fittingly, repo-airlock also scans itself in CI. Its detectors' own source necessarily contains
private-IP CIDR literals, and the fixtures contain intentional fake secrets — both are acknowledged
in the checked-in `.airlock-baseline.json` (via the same `--baseline` workflow a real user would
use), so the self-scan ends `CLEARED` without weakening a single detector.

## License

MIT © 2026 Andrew Lazzeroni. See [LICENSE](LICENSE).
