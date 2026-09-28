# Extraction Rules

Use this reference only when the main workflow needs extra judgment on noisy pages.

## Content Classification

- `vulnerability-content`: multiple strong indicators such as CVE IDs, severity labels, affected versions, remediation text, or advisory titles.
- `possible-vulnerability-content`: some indicators are present, but the page may be a blog post, changelog, or aggregator.
- `generic-html`: readable HTML without enough vulnerability signals.
- `javascript-or-static-asset`: bundled JavaScript, CSS, images, fonts, sourcemaps, or other static assets.
- `empty-or-low-value`: too little readable text to support extraction.

## Extraction Heuristics

- Prefer exact CVE identifiers over inferred vulnerability names.
- Prefer vendor-supplied remediation text over generic summaries.
- Keep extracted fields empty when evidence is weak; do not hallucinate product names, versions, or fixes.
- Use `text_excerpt` and `evidence` to justify edge-case decisions.

## Practical Notes

- Some advisories embed key fields in prose rather than a neat table; the script uses regex heuristics to capture both.
- Some sites return error pages with HTTP 200. Treat a friendly error page as invalid if it has almost no security keywords.
- If a site is inaccessible directly, rerun with `HTTP_PROXY` and `HTTPS_PROXY` set, or pass `--proxy`.
