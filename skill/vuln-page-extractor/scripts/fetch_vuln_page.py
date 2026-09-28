#!/usr/bin/env python3
"""
Fetch one or more URLs, classify the response, and extract vulnerability details.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import socket
import ssl
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html import unescape
from html.parser import HTMLParser
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


DEFAULT_TIMEOUT = 20.0
DEFAULT_CONCURRENCY = 6
MAX_EVIDENCE_ITEMS = 10
MAX_REFERENCES = 20
MAX_TEXT_CHARS = 120000
USER_AGENT = (
    "Mozilla/5.0 (compatible; VulnPageExtractor/1.0; +https://openai.com)"
)

SEVERITY_PATTERN = re.compile(
    r"\b(critical|high|medium|moderate|low|important)\b", re.IGNORECASE
)
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CVSS_PATTERN = re.compile(r"\bCVSS(?:\s*v?3(?:\.\d)?)?[:\s]+([0-9]{1,2}(?:\.[0-9])?)\b", re.IGNORECASE)
DATE_PATTERN = re.compile(
    r"\b(?:20\d{2}|19\d{2})[-/](?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12]\d|3[01])\b"
)
VERSION_PATTERN = re.compile(
    r"\b(?:versions?|releases?)\s*(?:affected|before|through|<=|<|:)?\s*([A-Za-z0-9._,\- ]{2,80})",
    re.IGNORECASE,
)
VENDOR_PATTERN = re.compile(r"\b(?:vendor|publisher|maintainer)\s*[:\-]\s*([^\n|]{2,80})", re.IGNORECASE)
PRODUCT_PATTERN = re.compile(
    r"\b(?:affected product|affected component|affected products|product|component)\s*[:\-]\s*([^\n|]{2,120})",
    re.IGNORECASE,
)
PUBLISHED_PATTERN = re.compile(
    r"\b(?:published|release date|initial release)\s*[:\-]\s*([^\n|]{4,40})",
    re.IGNORECASE,
)
UPDATED_PATTERN = re.compile(
    r"\b(?:updated|last updated|modified)\s*[:\-]\s*([^\n|]{4,40})",
    re.IGNORECASE,
)
FIX_PATTERN = re.compile(
    r"\b(?:fixed in|patched in|upgrade to|apply patch|resolved in)\b([^\n.]{0,120})",
    re.IGNORECASE,
)
WORKAROUND_PATTERN = re.compile(
    r"\b(?:workaround|mitigation|temporary fix)\b([^\n.]{0,160})",
    re.IGNORECASE,
)

CONTENT_KEYWORDS = {
    "vulnerability",
    "cve-",
    "security advisory",
    "advisory",
    "affected versions",
    "severity",
    "cvss",
    "exploit",
    "patch",
    "remediation",
    "mitigation",
    "workaround",
    "impact",
    "vendor",
    "product",
}

STATIC_EXTENSIONS = {
    ".js",
    ".mjs",
    ".css",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".pdf",
    ".zip",
}


class LinkAndTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_script = False
        self.in_style = False
        self.text_parts: List[str] = []
        self.title_parts: List[str] = []
        self.links: List[Dict[str, str]] = []
        self.meta: Dict[str, str] = {}
        self._current_title = False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attr_map = {key.lower(): (value or "") for key, value in attrs}
        if tag == "script":
            self.in_script = True
        elif tag == "style":
            self.in_style = True
        elif tag == "title":
            self._current_title = True
        elif tag == "a":
            href = attr_map.get("href", "").strip()
            text = attr_map.get("title", "").strip()
            if href:
                self.links.append({"href": href, "text": text})
        elif tag == "meta":
            name = attr_map.get("name", "") or attr_map.get("property", "")
            content = attr_map.get("content", "")
            if name and content:
                self.meta[name.lower()] = content.strip()

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self.in_script = False
        elif tag == "style":
            self.in_style = False
        elif tag == "title":
            self._current_title = False

    def handle_data(self, data: str) -> None:
        if self.in_script or self.in_style:
            return
        cleaned = clean_whitespace(data)
        if not cleaned:
            return
        if self._current_title:
            self.title_parts.append(cleaned)
        self.text_parts.append(cleaned)


def clean_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def dedupe_preserve(items: Iterable[str]) -> List[str]:
    seen = set()
    output = []
    for item in items:
        normalized = clean_whitespace(item)
        if not normalized:
            continue
        lowered = normalized.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        output.append(normalized)
    return output


def clamp_text(value: str, limit: int = MAX_TEXT_CHARS) -> str:
    if len(value) <= limit:
        return value
    return value[:limit]


@dataclass
class FetchResult:
    url: str
    final_url: str
    http_status: Optional[int]
    content_type: str
    body: str
    proxy_used: Optional[str]
    error: Optional[str]


def load_urls(args: argparse.Namespace) -> List[str]:
    urls: List[str] = []
    if args.url:
        urls.extend(args.url)
    if args.input:
        with open(args.input, "r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    urls.append(stripped)
    unique = []
    seen = set()
    for url in urls:
        if url not in seen:
            unique.append(url)
            seen.add(url)
    return unique


def normalize_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme:
        return url
    return f"https://{url}"


def proxy_candidates(explicit_proxy: Optional[str]) -> List[str]:
    candidates = []
    if explicit_proxy:
        candidates.append(explicit_proxy)
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
        value = os.environ.get(key)
        if value:
            candidates.append(value)
    fallback = "http://127.0.0.1:7890"
    candidates.append(fallback)
    return dedupe_preserve(candidates)


def build_opener(proxy: Optional[str]) -> urllib.request.OpenerDirector:
    handlers: List[urllib.request.BaseHandler] = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    context = ssl.create_default_context()
    handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


def read_response(response: urllib.response.addinfourl) -> Tuple[str, str]:
    raw = response.read()
    content_type = response.headers.get("Content-Type", "")
    charset = response.headers.get_content_charset() or "utf-8"
    try:
        body = raw.decode(charset, errors="replace")
    except LookupError:
        body = raw.decode("utf-8", errors="replace")
    return body, content_type


def fetch_once(url: str, timeout: float, proxy: Optional[str]) -> FetchResult:
    opener = build_opener(proxy)
    request = urllib.request.Request(
        url=normalize_url(url),
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            body, content_type = read_response(response)
            status = getattr(response, "status", None) or response.getcode()
            final_url = response.geturl()
            return FetchResult(
                url=url,
                final_url=final_url,
                http_status=status,
                content_type=content_type,
                body=body,
                proxy_used=proxy,
                error=None,
            )
    except urllib.error.HTTPError as exc:
        try:
            body, content_type = read_response(exc)
        except Exception:
            body, content_type = "", exc.headers.get("Content-Type", "")
        return FetchResult(
            url=url,
            final_url=exc.geturl() if hasattr(exc, "geturl") else normalize_url(url),
            http_status=exc.code,
            content_type=content_type,
            body=body,
            proxy_used=proxy,
            error=f"HTTP {exc.code}",
        )
    except (urllib.error.URLError, socket.timeout, TimeoutError, ssl.SSLError, ConnectionError) as exc:
        return FetchResult(
            url=url,
            final_url=normalize_url(url),
            http_status=None,
            content_type="",
            body="",
            proxy_used=proxy,
            error=str(exc),
        )


def should_retry_with_proxy(result: FetchResult) -> bool:
    if not result.error:
        return False
    lowered = result.error.lower()
    retry_terms = ("timed out", "tunnel", "connection", "refused", "reset", "unreachable", "temporary failure", "name or service not known")
    return any(term in lowered for term in retry_terms)


def classify_payload(url: str, content_type: str, body: str, title: str, text: str) -> Tuple[str, float, List[str]]:
    evidence: List[str] = []
    path = urllib.parse.urlparse(url).path.lower()
    suffix = ""
    if "." in path.rsplit("/", 1)[-1]:
        suffix = "." + path.rsplit(".", 1)[-1]

    lowered_type = (content_type or "").lower()
    lowered_body_head = body[:300].lower()
    lowered_text = text.lower()

    if suffix in STATIC_EXTENSIONS or "javascript" in lowered_type or "text/css" in lowered_type:
        evidence.append(f"content-type={content_type or 'unknown'}")
        return "javascript-or-static-asset", 0.99, evidence

    if lowered_body_head.startswith("function(") or lowered_body_head.startswith("(()=>") or lowered_body_head.startswith("!function("):
        evidence.append("body starts like bundled JavaScript")
        return "javascript-or-static-asset", 0.95, evidence

    if len(text.strip()) < 80:
        evidence.append("very little readable text")
        return "empty-or-low-value", 0.85, evidence

    hits = []
    for keyword in CONTENT_KEYWORDS:
        if keyword in lowered_text:
            hits.append(keyword)
    if title and any(word in title.lower() for word in ("cve", "advisory", "vulnerability", "security")):
        hits.append("title-match")
    if CVE_PATTERN.search(text):
        hits.append("cve-id")
    if SEVERITY_PATTERN.search(text):
        hits.append("severity")
    if CVSS_PATTERN.search(text):
        hits.append("cvss")

    evidence.extend(dedupe_preserve(hits)[:MAX_EVIDENCE_ITEMS])
    score = min(1.0, 0.2 + 0.1 * len(dedupe_preserve(hits)))
    if len(hits) >= 5:
        return "vulnerability-content", score, evidence
    if len(hits) >= 2:
        return "possible-vulnerability-content", score, evidence
    return "generic-html", max(0.2, score), evidence or ["html page without strong vulnerability markers"]


def parse_html(body: str) -> Tuple[str, str, List[Dict[str, str]], Dict[str, str]]:
    parser = LinkAndTextParser()
    parser.feed(body)
    title = clean_whitespace(" ".join(parser.title_parts))
    text = clamp_text(unescape(" ".join(parser.text_parts)))
    return title, text, parser.links, parser.meta


def find_matches(pattern: re.Pattern[str], text: str, limit: int = 20) -> List[str]:
    output = []
    for match in pattern.finditer(text):
        if match.groups():
            candidate = match.group(1)
        else:
            candidate = match.group(0)
        output.append(clean_whitespace(candidate))
        if len(output) >= limit:
            break
    return dedupe_preserve(output)


def infer_summary(text: str) -> str:
    sentences = re.split(r"(?<=[.!?])\s+", text)
    scored: List[Tuple[int, str]] = []
    for sentence in sentences:
        cleaned = clean_whitespace(sentence)
        if len(cleaned) < 40:
            continue
        score = 0
        lowered = cleaned.lower()
        if "vulnerability" in lowered or "cve-" in lowered:
            score += 3
        if "allow" in lowered or "could" in lowered or "impact" in lowered:
            score += 1
        if "affected" in lowered or "patch" in lowered or "remote code execution" in lowered:
            score += 2
        scored.append((score, cleaned))
    scored.sort(key=lambda item: (-item[0], len(item[1])))
    return scored[0][1] if scored else ""


def extract_references(base_url: str, links: Sequence[Dict[str, str]]) -> List[str]:
    output = []
    for link in links:
        href = clean_whitespace(link.get("href", ""))
        if not href:
            continue
        absolute = urllib.parse.urljoin(base_url, href)
        output.append(absolute)
        if len(output) >= MAX_REFERENCES:
            break
    return dedupe_preserve(output)


def extract_vulnerability_data(result: FetchResult) -> Dict[str, object]:
    title = ""
    text = ""
    links: List[Dict[str, str]] = []
    meta: Dict[str, str] = {}

    if "html" in (result.content_type or "").lower() or "<html" in result.body.lower():
        title, text, links, meta = parse_html(result.body)
    else:
        text = clamp_text(clean_whitespace(result.body))

    classification, confidence, evidence = classify_payload(
        result.final_url,
        result.content_type,
        result.body,
        title,
        text,
    )

    meta_title = meta.get("og:title") or meta.get("twitter:title") or ""
    page_title = title or meta_title
    cve_ids = dedupe_preserve(CVE_PATTERN.findall(text))
    severity = dedupe_preserve(find_matches(SEVERITY_PATTERN, text, limit=5))
    cvss_scores = dedupe_preserve(find_matches(CVSS_PATTERN, text, limit=5))
    affected_products = find_matches(PRODUCT_PATTERN, text, limit=10)
    affected_versions = find_matches(VERSION_PATTERN, text, limit=10)
    vendor = find_matches(VENDOR_PATTERN, text, limit=5)
    published = find_matches(PUBLISHED_PATTERN, text, limit=3)
    updated = find_matches(UPDATED_PATTERN, text, limit=3)
    fixes = find_matches(FIX_PATTERN, text, limit=8)
    workarounds = find_matches(WORKAROUND_PATTERN, text, limit=8)

    if not published:
        published = find_matches(DATE_PATTERN, text, limit=2)
    if not updated:
        remaining_dates = find_matches(DATE_PATTERN, text, limit=4)
        updated = [date for date in remaining_dates if date not in published][:2]

    if not affected_products and page_title:
        guessed = re.split(r"[:|\-]", page_title)[0]
        if guessed and "cve" not in guessed.lower():
            affected_products = [clean_whitespace(guessed)]

    references = extract_references(result.final_url, links)
    summary = infer_summary(text)

    return {
        "source_url": result.url,
        "final_url": result.final_url,
        "http_status": result.http_status,
        "content_type": result.content_type,
        "proxy_used": result.proxy_used,
        "fetch_error": result.error,
        "page_title": page_title,
        "classification": classification,
        "confidence": round(confidence, 2),
        "summary": summary,
        "cve_ids": cve_ids,
        "severity": severity,
        "cvss_scores": cvss_scores,
        "vendor": vendor,
        "affected_products": affected_products,
        "affected_versions": affected_versions,
        "published": published,
        "updated": updated,
        "fixes": fixes,
        "workarounds": workarounds,
        "references": references,
        "evidence": evidence,
        "text_excerpt": text[:1200],
    }


def fetch_with_fallback(url: str, timeout: float, explicit_proxy: Optional[str]) -> Dict[str, object]:
    initial_proxy = explicit_proxy
    first_result = fetch_once(url, timeout, initial_proxy)
    if explicit_proxy or not should_retry_with_proxy(first_result):
        return extract_vulnerability_data(first_result)

    for proxy in proxy_candidates(explicit_proxy):
        if proxy == initial_proxy:
            continue
        retried = fetch_once(url, timeout, proxy)
        if not retried.error or retried.http_status:
            data = extract_vulnerability_data(retried)
            data["retry_strategy"] = "proxy-fallback"
            return data

    data = extract_vulnerability_data(first_result)
    data["retry_strategy"] = "direct-only"
    return data


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", action="append", help="Target URL. Repeat for multiple URLs.")
    parser.add_argument("--input", help="Path to a text file that contains one URL per line.")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Worker count for concurrent fetching.")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request timeout in seconds.")
    parser.add_argument("--proxy", help="Explicit proxy URL, such as http://127.0.0.1:7890")
    parser.add_argument("--output", help="Write JSON output to this file.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    urls = load_urls(args)
    if not urls:
        print("Provide --url or --input with at least one URL.", file=sys.stderr)
        return 2

    lock = threading.Lock()
    results: List[Optional[Dict[str, object]]] = [None] * len(urls)

    def worker(index_and_url: Tuple[int, str]) -> None:
        index, url = index_and_url
        result = fetch_with_fallback(url, args.timeout, args.proxy)
        with lock:
            results[index] = result

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as executor:
        list(executor.map(worker, list(enumerate(urls))))

    final_results = [item for item in results if item is not None]
    output = {
        "url_count": len(urls),
        "results": final_results,
    }

    serialized = json.dumps(output, indent=2 if args.pretty else None, ensure_ascii=False)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(serialized)
            handle.write("\n")
    print(serialized)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
