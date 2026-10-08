"""A deliberately-vulnerable demo target (stdlib only) for showcasing the pipeline.

Plants issues that different detectors catch, with NO external tools required:
  - multiple linked pages + params   → crawler discovers them
  - /search reflects input unescaped → XSS canary (needs Playwright)
  - /product?id=' triggers a SQL error → built-in error-based SQLi check
  - /admin/users: denied to anonymous, but allowed to ANY logged-in cookie
    → privilege-escalation check (with two cookie roles: admin + user)
  - planted JWT / AWS key / email    → JWT + secret scraper

Start it with start_demo(); it returns the base URL.
"""

from __future__ import annotations

import base64
import http.server
import socketserver
import threading
from urllib.parse import parse_qs, urlparse

PORT = 8911

_alg_none = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
_payload = base64.urlsafe_b64encode(b'{"user":"admin","role":"admin"}').decode().rstrip("=")
JWT = f"{_alg_none}.{_payload}."

HOME = f"""<!doctype html><html><body>
<h1>Totally Secure Shop</h1>
<ul>
  <li><a href="/product.php?id=1">Product 1</a></li>
  <li><a href="/product.php?id=2">Product 2</a></li>
  <li><a href="/listproducts.php?cat=3">Category 3</a></li>
  <li><a href="/search.php?q=shoes">Search</a></li>
  <li><a href="/admin/users">Admin: users</a></li>
  <li><a href="/.git/config">config</a></li>
</ul>
<!-- session={JWT} aws=AKIAIOSFODNN7EXAMPLE contact=admin@totallysecure.local -->
</body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code: int, body: str):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):  # noqa: N802
        p = urlparse(self.path)
        qs = parse_qs(p.query)
        cookie = self.headers.get("Cookie", "")

        if p.path == "/admin/users":
            # BUG: any logged-in cookie is accepted; anonymous is denied.
            if "session=" in cookie:
                return self._send(200, "<html><body>Admin panel — user list: alice, bob, admin</body></html>")
            return self._send(403, "<html><body>403 Forbidden — login required</body></html>")

        if p.path in ("/product.php", "/listproducts.php"):
            val = (qs.get("id") or qs.get("cat") or [""])[0]
            # BUG: a single quote breaks the "query" → SQL error leaks.
            if "'" in val:
                return self._send(500, "<html><body>Error: You have an error in your SQL syntax near '''</body></html>")
            return self._send(200, "<html><body>item<!-- aws=AKIAIOSFODNN7EXAMPLE --></body></html>")

        if p.path == "/search.php":
            q = (qs.get("q") or [""])[0]
            # BUG: reflected unescaped → XSS.
            return self._send(200, f"<html><body>Results for: {q}</body></html>")

        return self._send(200, HOME)

    def log_message(self, *a):  # quiet
        pass


def start_demo(port: int = PORT) -> str:
    """Start the demo server in a background thread; return its base URL."""
    srv = socketserver.TCPServer(("127.0.0.1", port), Handler)
    srv.allow_reuse_address = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}/"


if __name__ == "__main__":
    url = start_demo()
    print(f"Vulnerable demo target on {url}  (Ctrl+C to stop)")
    import time
    while True:
        time.sleep(3600)
