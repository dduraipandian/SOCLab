"""c2-sim: the made-up attacker server at 203.0.113.50:8443 (documentation range, owned by no one)."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOL = b"#!/bin/sh\n# made-up attacker tool for the lab\necho beacon\n"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = {"/beacon": b"ok\n", "/tool": TOOL}.get(self.path)
        self.send_response(200 if body else 404)
        self.send_header("Content-Length", str(len(body or b"")))
        self.end_headers()
        self.wfile.write(body or b"")

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8443), Handler).serve_forever()
