"""A small, dependency-free HTTP crawler.

Gives Phase 1 a way to discover a site's own attack surface (pages, links,
forms, query-parameterized URLs, JS files) without requiring ffuf/katana, and to
capture the fetched pages so later phases have request/response bodies to analyze.

HTML parsing (:func:`parse_html`) is pure and unit-testable. Network fetching is
isolated in :func:`default_fetch` so it can be swapped in tests.
"""

from __future__ import annotations

import urllib.request
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlparse

USER_AGENT = "ReconToReport/0.1 (+authorized-testing)"


@dataclass
class Page:
    url: str
    status: int | None
    headers: dict[str, str]
    body: str


@dataclass
class ParsedLinks:
    links: set[str] = field(default_factory=set)
    scripts: set[str] = field(default_factory=set)
    forms: list[dict] = field(default_factory=list)  # {action, method, params:[names]}


class _LinkParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base = base_url
        self.out = ParsedLinks()
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.out.links.add(urljoin(self.base, a["href"]))
        elif tag == "script" and a.get("src"):
            self.out.scripts.add(urljoin(self.base, a["src"]))
        elif tag == "link" and a.get("href"):
            self.out.links.add(urljoin(self.base, a["href"]))
        elif tag == "form":
            action = urljoin(self.base, a.get("action") or self.base)
            self._form = {"action": action, "method": (a.get("method") or "GET").upper(), "params": []}
        elif tag in ("input", "textarea", "select") and self._form is not None:
            name = a.get("name")
            if name:
                self._form["params"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.out.forms.append(self._form)
            self._form = None


def parse_html(base_url: str, html: str) -> ParsedLinks:
    p = _LinkParser(base_url)
    try:
        p.feed(html)
    except Exception:
        pass
    if p._form is not None:  # unclosed form
        p.out.forms.append(p._form)
    return p.out


def default_fetch(url: str, timeout: int = 15) -> Page | None:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read(2_000_000)  # cap at ~2MB
            ctype = resp.headers.get("Content-Type", "")
            body = raw.decode("utf-8", errors="replace") if raw else ""
            return Page(
                url=url,
                status=resp.status,
                headers={k: v for k, v in resp.headers.items()},
                body=body if "text" in ctype or "json" in ctype or "html" in ctype else "",
            )
    except urllib.error.HTTPError as e:  # type: ignore[attr-defined]
        return Page(url=url, status=e.code, headers={}, body="")
    except Exception:
        return None


def crawl(
    start_url: str,
    in_scope,                      # callable(host:str) -> bool
    fetch=default_fetch,
    max_pages: int = 50,
    max_depth: int = 2,
) -> list[Page]:
    """Breadth-first crawl, same-scope only. Returns the fetched pages.

    Callers read each Page's parsed links via :func:`parse_html` as needed; this
    returns the raw pages so the phase can both persist transactions and expand
    assets from one pass.
    """
    seen: set[str] = set()
    pages: list[Page] = []
    queue: deque[tuple[str, int]] = deque([(urldefrag(start_url)[0], 0)])

    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        if url in seen:
            continue
        seen.add(url)
        host = urlparse(url).hostname or ""
        if not in_scope(host):
            continue
        page = fetch(url)
        if page is None:
            continue
        pages.append(page)

        if depth < max_depth and page.body:
            parsed = parse_html(url, page.body)
            for link in list(parsed.links) + [f["action"] for f in parsed.forms]:
                link = urldefrag(link)[0]
                if link.startswith(("http://", "https://")) and link not in seen:
                    queue.append((link, depth + 1))
    return pages
