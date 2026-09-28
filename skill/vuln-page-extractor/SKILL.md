---
name: vuln-page-extractor
description: Fetch one or more public URLs that may contain vulnerability advisories, CVE records, bulletin pages, or exploit writeups; classify whether each response is a real content page, a JavaScript/static asset, or an invalid/empty response; and extract structured vulnerability details such as title, CVE IDs, severity, affected products, versions, remediation, references, and raw evidence. Use when Codex is asked to visit links and return vulnerability details, especially when multiple links should be processed concurrently or when direct access may require proxy fallback.
---

# Vuln Page Extractor

## Overview

Fetch suspect advisory URLs, decide whether the response is worth analyzing, and return structured vulnerability data with supporting evidence. Prefer the bundled script for repeatable fetching, concurrency, proxy fallback, and normalized output.

## Workflow

1. Put the target URLs into a text file or pass them directly with repeated `--url`.
2. Run `scripts/fetch_vuln_page.py` first. It handles concurrent requests, retry plans, proxy fallback, and extraction.
3. Read the JSON result and report only entries whose `classification` is `vulnerability-content` or `possible-vulnerability-content`.
4. If every response is blocked or low-value, retry with a proxy before giving up.

## Run The Script

Single URL:

```bash
python3 scripts/fetch_vuln_page.py \
  --url "https://example.com/advisory" \
  --pretty
```

Multiple URLs with concurrency:

```bash
python3 scripts/fetch_vuln_page.py \
  --input urls.txt \
  --concurrency 8 \
  --pretty
```

Force a proxy immediately:

```bash
python3 scripts/fetch_vuln_page.py \
  --input urls.txt \
  --proxy http://127.0.0.1:7890 \
  --pretty
```

Retry with shell proxy variables when direct access fails:

```bash
export HTTP_PROXY=http://127.0.0.1:7890
export HTTPS_PROXY=http://127.0.0.1:7890
python3 scripts/fetch_vuln_page.py --input urls.txt --pretty
```

## Proxy Rules

- The script always tries direct access first unless `--proxy` is passed.
- If direct access fails, the script retries with proxy candidates from `--proxy`, `HTTPS_PROXY`, `HTTP_PROXY`, `https_proxy`, `http_proxy`, then `http://127.0.0.1:7890`.
- If you are driving the workflow manually and a site is still unreachable, explicitly export `HTTP_PROXY` and `HTTPS_PROXY` and rerun.

## Classification Rules

- Treat `classification=javascript-or-static-asset` as non-actionable unless the user explicitly asked for asset inspection.
- Treat `classification=empty-or-low-value` as a failed advisory lookup.
- Treat `classification=possible-vulnerability-content` as usable, but verify extracted fields against `evidence`.
- Treat `classification=vulnerability-content` as the strongest match.

## Reporting Rules

- Report the source URL, final URL, HTTP status, page title, classification, confidence, and extracted vulnerability fields.
- Include `cve_ids`, `severity`, `affected_products`, `affected_versions`, `vendor`, `published`, `updated`, `fixes`, `workarounds`, `references`, and a short summary when available.
- If extraction is partial, say which fields are missing instead of inventing values.
- Use `evidence` snippets for support, not long raw dumps.

## Output Notes

- The script prints JSON to stdout.
- Use `--pretty` for readable output.
- Use `--output result.json` to save artifacts for later summarization.
- Read [references/extraction-rules.md](references/extraction-rules.md) only when you need a deeper explanation of field heuristics or noisy-page handling.
