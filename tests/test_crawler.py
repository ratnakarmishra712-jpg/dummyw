"""Tests for the built-in crawler (parsing + BFS with a fake fetcher)."""

from __future__ import annotations

from recontoreport.tools.crawler import Page, crawl, parse_html


def test_parse_html_extracts_links_scripts_forms():
    html = """
    <html><body>
      <a href="/about">About</a>
      <a href="https://other.com/x">external</a>
      <script src="/static/app.js"></script>
      <form action="/login" method="post">
        <input name="user"><input name="pass"><input>
      </form>
    </body></html>
    """
    parsed = parse_html("https://example.com/", html)
    assert "https://example.com/about" in parsed.links
    assert "https://other.com/x" in parsed.links
    assert "https://example.com/static/app.js" in parsed.scripts
    assert len(parsed.forms) == 1
    form = parsed.forms[0]
    assert form["action"] == "https://example.com/login"
    assert form["method"] == "POST"
    assert form["params"] == ["user", "pass"]


def test_crawl_bfs_same_scope_with_fake_fetch():
    pages_html = {
        "https://example.com/": '<a href="/a">a</a><a href="/b">b</a><a href="https://evil.com/x">x</a>',
        "https://example.com/a": '<a href="/c">c</a>',
        "https://example.com/b": "no links",
        "https://example.com/c": "leaf",
    }

    def fake_fetch(url, timeout=15):
        body = pages_html.get(url)
        if body is None:
            return None
        return Page(url=url, status=200, headers={"Content-Type": "text/html"}, body=body)

    def in_scope(host):
        return host == "example.com"

    pages, errors = crawl("https://example.com/", in_scope=in_scope, fetch=fake_fetch,
                          max_pages=50, max_depth=2)
    urls = {p.url for p in pages}
    assert "https://example.com/" in urls
    assert "https://example.com/a" in urls
    assert "https://example.com/b" in urls
    # /c is depth 2 (home->a->c), within max_depth
    assert "https://example.com/c" in urls
    # evil.com is out of scope -> never fetched
    assert all("evil.com" not in u for u in urls)


def test_crawl_respects_max_pages():
    def fake_fetch(url, timeout=15):
        # every page links to two new unique pages
        n = url.rsplit("/", 1)[-1] or "0"
        body = f'<a href="/{n}0">x</a><a href="/{n}1">y</a>'
        return Page(url=url, status=200, headers={}, body=body)

    pages, errors = crawl("https://example.com/", in_scope=lambda h: True,
                          fetch=fake_fetch, max_pages=5, max_depth=10)
    assert len(pages) == 5


def test_crawl_reports_network_errors():
    from recontoreport.tools.crawler import Page

    def failing_fetch(url, timeout=20):
        return Page(url=url, status=None, headers={}, body="", error="TimeoutError: timed out")

    pages, errors = crawl("https://down.example/", in_scope=lambda h: True,
                          fetch=failing_fetch, max_pages=5, max_depth=1)
    assert pages == []
    assert errors and "TimeoutError" in errors[0][1]
