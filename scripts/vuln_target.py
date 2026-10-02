#!/usr/bin/env python3
"""A tiny, deliberately-vulnerable local target for testing ReconToReport.

Zero dependencies (Python stdlib only). Run it, then scan http://127.0.0.1:8911/.
It is NOT a real app — it only plants findings the pipeline can detect:
  - parameterized pages (?id=, ?q=) for the XSS/sqlmap steps
  - a reflected parameter (echoes input unescaped) for the XSS canary
  - a JWT with alg=none in a comment (Phase 4 flags it critical)
  - an AWS key + email in the body (Phase 5 secret scraper)

Usage:
    python scripts/vuln_target.py        # serves on http://127.0.0.1:8911/
"""

from __future__ import annotations

import base64
import http.server
import socketserver
from urllib.parse import parse_qs, urlparse

PORT = 8911
_alg_none = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
_payload = base64.urlsafe_b64encode(b'{"user":"admin","role":"admin"}').decode().rstrip("=")
JWT = f"{_alg_none}.{_payload}."

HOME = f"""<!doctype html><html><body>
<h1>Totally Secure Shop</h1>
<ul>
  <li><a href="/product.php?id=1">Product 1</a></li>
  <li><a href="/listproducts.php?cat=2">Category 2</a></li>
  <li><a href="/search.php?q=shoes">Search</a></li>
  <li><a href="/.git/config">config</a></li>
</ul>
<!-- session={JWT} aws=AKIAIOSFODNN7EXAMPLE contact=admin@totallysecure.local -->
</body></html>"""


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        if parsed.path == "/search.php":
            # Reflected, unescaped -> reflected-XSS canary will catch it.
            q = (qs.get("q") or [""])[0]
            body = f"<html><body>Results for: {q}<a href='/product.php?id=1'>back</a></body></html>"
        elif parsed.path in ("/product.php", "/listproducts.php"):
            body = "<html><body>item<!-- aws=AKIAIOSFODNN7EXAMPLE --></body></html>"
        else:
            body = HOME
        self.wfile.write(body.encode())

    def log_message(self, *a):  # quiet
        pass


if __name__ == "__main__":
    print(f"Vulnerable test target on http://127.0.0.1:{PORT}/  (Ctrl+C to stop)")
    socketserver.TCPServer(("127.0.0.1", PORT), H).serve_forever()
