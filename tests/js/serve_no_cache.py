"""Static file server for tests/js/app_test.html, rooted at the repo root.

`python -m http.server` sends no Cache-Control header at all, so a browser is
free to (and, observed directly: does) cache app.js across navigations and
even across brand-new tabs -- a change on disk can then silently keep
reporting the OLD file's results as "17/17 passed" until the browser's cache
is cleared some other way. That defeats the one thing a regression suite
exists for. The real `rhino web` server already sends `Cache-Control:
no-cache` on the page and static assets for the identical reason (see
`web/app.py`); this is the same fix, for the same reason, for this one-file
throwaway server, since `python -m http.server` has no flag for it.

Run via the `rhino-js-tests` entry in `.claude/launch.json` (preview_start),
or directly: `python tests/js/serve_no_cache.py [port]` (default 8500) from
the repo root. Open http://localhost:<port>/tests/js/app_test.html.
"""

import functools
import http.server
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class NoCacheHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        super().end_headers()


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8500
    handler = functools.partial(NoCacheHandler, directory=str(REPO_ROOT))
    with http.server.ThreadingHTTPServer(("127.0.0.1", port), handler) as httpd:
        print(f"Serving {REPO_ROOT} at http://127.0.0.1:{port}/tests/js/app_test.html (no-cache)")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
