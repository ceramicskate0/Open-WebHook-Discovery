"""Crawl one authorized site for potential webhook receiver endpoints."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import deque
from collections.abc import Iterable
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

RECEIVER_METHODS = {"POST", "PUT", "PATCH"}
SECRET_PARAMETER = re.compile(r"(token|secret|key|auth|signature|credential|password)", re.IGNORECASE)
XHR_CALL = re.compile(r"\.open\s*\(\s*(['\"])(POST|PUT|PATCH)\1\s*,\s*(['\"])(.*?)\3", re.IGNORECASE | re.DOTALL)
FETCH_CALL = re.compile(r"\bfetch\s*\(\s*(['\"`])([^'\"`]+)\1\s*,\s*\{[\s\S]{0,512}?\bmethod\s*:\s*(['\"])(POST|PUT|PATCH)\3", re.IGNORECASE)
METHOD_CALL = re.compile(r"\.(post|put|patch)\s*\(\s*(['\"`])([^'\"`]+)\2", re.IGNORECASE)


class DiscoveryError(Exception):
    """Raised when crawler settings or input are invalid."""


def normalize_domain(value: str) -> str:
    """Accept a hostname, not a URL, path, wildcard, or IP address."""
    candidate = value.strip().lower().rstrip(".")
    if not candidate or "://" in candidate or "/" in candidate or "*" in candidate:
        raise ValueError("Enter a hostname only, such as example.org")
    if any(not label or len(label) > 63 for label in candidate.split(".")):
        raise ValueError("The hostname is not valid")
    if len(candidate) > 253 or not re.fullmatch(r"[a-z0-9.-]+", candidate):
        raise ValueError("The hostname is not valid")
    return candidate


def is_in_scope(hostname: str | None, domain: str) -> bool:
    if not hostname:
        return False
    normalized_host = hostname.lower().rstrip(".")
    return normalized_host == domain or normalized_host.endswith("." + domain)


def is_same_origin(candidate: str, origin: str) -> bool:
    target = urlsplit(candidate)
    base = urlsplit(origin)
    if target.scheme not in {"http", "https"} or target.hostname is None:
        return False
    try:
        target_port = target.port or (443 if target.scheme == "https" else 80)
        base_port = base.port or (443 if base.scheme == "https" else 80)
    except ValueError:
        return False
    return target.scheme == base.scheme and target.hostname.lower() == base.hostname.lower() and target_port == base_port


def redact_url(raw_url: str) -> str:
    """Remove URL credentials and query values before displaying a result."""
    parts = urlsplit(raw_url)
    hostname = parts.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc = hostname
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    safe_query = [
        (key, "REDACTED" if SECRET_PARAMETER.search(key) else value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunsplit((parts.scheme, netloc, parts.path, urlencode(safe_query), ""))


class SiteParser(HTMLParser):
    def __init__(self, page_url: str):
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[tuple[str, str]] = []
        self.inline_scripts: list[str] = []
        self._in_inline_script = False
        self._script_buffer: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag in {"a", "area"} and attributes.get("href"):
            self.links.append(urljoin(self.page_url, attributes["href"]))
        elif tag == "script":
            if attributes.get("src"):
                self.scripts.append(urljoin(self.page_url, attributes["src"]))
            else:
                self._in_inline_script = True
                self._script_buffer = []
        elif tag == "form":
            method = (attributes.get("method") or "GET").upper()
            if method in RECEIVER_METHODS:
                action = urljoin(self.page_url, attributes.get("action") or self.page_url)
                self.forms.append((method, action))

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._in_inline_script:
            self.inline_scripts.append("".join(self._script_buffer))
            self._script_buffer = []
            self._in_inline_script = False

    def handle_data(self, data: str) -> None:
        if self._in_inline_script:
            self._script_buffer.append(data)


def extract_script_candidates(script: str) -> list[tuple[str, str]]:
    found = [(match.group(2).upper(), match.group(4)) for match in XHR_CALL.finditer(script)]
    found.extend((match.group(4).upper(), match.group(2)) for match in FETCH_CALL.finditer(script))
    found.extend((match.group(1).upper(), match.group(3)) for match in METHOD_CALL.finditer(script))
    return found


def _candidate(method: str, raw_url: str, source_page: str, origin: str) -> dict[str, str] | None:
    resolved_url = urljoin(source_page, raw_url)
    if not is_same_origin(resolved_url, origin):
        return None
    return {
        "method": method.upper(),
        "url": redact_url(resolved_url),
        "source_page": redact_url(source_page),
    }


class ScopedRedirectHandler(HTTPRedirectHandler):
    def __init__(self, origin: str):
        super().__init__()
        self.origin = origin

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        if not is_same_origin(new_url, self.origin):
            return None
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


def _fetch_text(url: str, origin: str, timeout: float, max_bytes: int) -> tuple[str, str, str] | None:
    request = Request(url, headers={
        "Accept": "text/html,application/javascript,*/*;q=0.5",
        "User-Agent": "webhook-discovery/0.1 (authorized, bounded crawler)",
    })
    try:
        opener = build_opener(ScopedRedirectHandler(origin))
        with opener.open(request, timeout=timeout) as response:
            content_type = response.headers.get_content_type()
            charset = response.headers.get_content_charset() or "utf-8"
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                return None
            return body.decode(charset, errors="replace"), response.geturl(), content_type
    except (HTTPError, URLError, TimeoutError, OSError, LookupError):
        return None


def discover(domain: str, max_pages: int = 30, max_requests: int = 200,
             delay: float = 0.5, timeout: float = 10.0, max_bytes: int = 1_000_000) -> list[dict[str, str]]:
    domain = normalize_domain(domain)
    if not 1 <= max_pages <= 500 or not 1 <= max_requests <= 2000:
        raise ValueError("max-pages must be 1-500 and max-requests must be 1-2000")
    if delay < 0 or timeout <= 0 or max_bytes < 1:
        raise ValueError("delay must be non-negative; timeout and max-bytes must be positive")

    origin = f"https://{domain}/"
    pages = deque([origin])
    visited_pages: set[str] = set()
    visited_scripts: set[str] = set()
    unique: dict[tuple[str, str], dict[str, str]] = {}
    request_count = 0

    def fetch(url: str) -> tuple[str, str, str] | None:
        nonlocal request_count
        if request_count >= max_requests or not is_same_origin(url, origin):
            return None
        if request_count and delay:
            time.sleep(delay)
        request_count += 1
        return _fetch_text(url, origin, timeout, max_bytes)

    while pages and len(visited_pages) < max_pages and request_count < max_requests:
        page_url = pages.popleft()
        if page_url in visited_pages or not is_same_origin(page_url, origin):
            continue
        visited_pages.add(page_url)
        fetched = fetch(page_url)
        if not fetched:
            continue
        body, final_url, content_type = fetched
        if content_type != "text/html":
            continue

        parser = SiteParser(final_url)
        parser.feed(body)
        parser.close()
        for method, target_url in parser.forms:
            candidate = _candidate(method, target_url, final_url, origin)
            if candidate:
                unique.setdefault((candidate["method"], candidate["url"]), candidate)

        for script_body in parser.inline_scripts:
            for method, target_url in extract_script_candidates(script_body):
                candidate = _candidate(method, target_url, final_url, origin)
                if candidate:
                    unique.setdefault((candidate["method"], candidate["url"]), candidate)

        for script_url in parser.scripts:
            if script_url in visited_scripts or not is_same_origin(script_url, origin):
                continue
            visited_scripts.add(script_url)
            script_result = fetch(script_url)
            if not script_result:
                continue
            script_body, script_final_url, _ = script_result
            for method, target_url in extract_script_candidates(script_body):
                candidate = _candidate(method, target_url, script_final_url, origin)
                if candidate:
                    unique.setdefault((candidate["method"], candidate["url"]), candidate)

        for link in parser.links:
            if is_same_origin(link, origin) and link not in visited_pages:
                pages.append(link)
    return list(unique.values())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Crawl one authorized site for potential receiver endpoints using only in-scope GET requests."
    )
    parser.add_argument("domain", help="authorized hostname to crawl; do not include a URL or wildcard")
    parser.add_argument("--max-pages", type=int, default=30, help="maximum HTML pages to visit (default: 30)")
    parser.add_argument("--max-requests", type=int, default=200, help="maximum same-origin GET requests including scripts")
    parser.add_argument("--delay", type=float, default=0.5, help="seconds between requests (default: 0.5)")
    parser.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds")
    parser.add_argument("--json", action="store_true", help="print results as JSON")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        domain = normalize_domain(args.domain)
        candidates = discover(domain, args.max_pages, args.max_requests, args.delay, args.timeout)
    except (ValueError, DiscoveryError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"domain": domain, "candidates": candidates}, indent=2))
    elif candidates:
        print(f"Potential receiver endpoints found for {domain} (not verified):")
        for candidate in candidates:
            print(f"{candidate['method']} {candidate['url']} [found on {candidate['source_page']}]")
    else:
        print(f"No potential receiver endpoints found within the crawl limits for {domain}.")
    print("Only same-origin GET requests were sent; findings are heuristic, not confirmed webhooks.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
