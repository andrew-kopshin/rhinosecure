# `app.js` regression tests

`src/rhinosecure/web/static/app.js` is plain vanilla JS -- no build step, no framework -- and
this project's toolchain is Python-only by deliberate choice (CLAUDE.md Section 11). There is no
Node.js/npm here, so this is a **browser-based harness**, not a `node`/`jest`/`vitest` suite:
`app_test.html` loads the real `app.js` (not a copy) and runs plain assertions against it in a
real browser's JS engine.

## Running it

The built-in browser pane cannot open `file://` URLs, so this needs an HTTP server in front of
it (a bare `python -m http.server` is not enough either -- see the note in `serve_no_cache.py`).

```powershell
.\.venv312\Scripts\python.exe tests\js\serve_no_cache.py
```

Then open `http://localhost:8500/tests/js/app_test.html` in a browser (the built-in browser
pane: `preview_start` with the `rhino-js-tests` entry in `.claude/launch.json` does both steps
in one call). Read the result three ways:

- the page title -- `N/M passed -- app.js tests`
- the `#test-report` block on the page (color-coded)
- `window.__TEST_RESULTS__` -- `{passed, failed, total, results: [{name, pass, error?}]}`, for
  reading from `javascript_tool` without scraping text

## Why a no-cache server, specifically

Confirmed live, not assumed: a plain `python -m http.server` sends no `Cache-Control` header,
and the browser cached `app.js` aggressively enough that editing the file on disk and reloading
-- even in a brand-new tab -- kept reporting the OLD file's results. That defeats the entire
point of a regression suite: it would report clean while looking at stale code. `serve_no_cache.py`
sends `Cache-Control: no-store, no-cache, must-revalidate` on every response, the same property
the real `rhino web` server already has (`Cache-Control: no-cache` on the page and static
assets, commit `71dd50d`). Always use `serve_no_cache.py`, never a bare `http.server`, for this.

## What's covered, and what isn't

Covers: that the whole file parses without a syntax error (spot-checked across functions near
the start, middle and end of the file -- a syntax error anywhere aborts parsing of the WHOLE
classic `<script>`, so this is the cheapest possible check with the broadest reach); `esc()`;
`recourseCommand()`/`recourseHtml()` (the printed CLI recourse text -- built to close CLAUDE.md's
"Resolve-slots: the zero-row panel closed, and a shipped syntax error caught before it landed"
entry, and this test file exists specifically because that fix shipped with a syntax error that
nothing had caught before a human happened to load it in a real JS engine); `renderResolvePanel()`
for the zero-row case and the ordinary correctable-row case.

Does **not** cover: `boot()`'s own fetch/render sequence, chat, uploads, jobs, or most of the
tab-rendering functions -- this is deliberately scoped to the code this session's bugs actually
touched, not a claim of full coverage. Extend it the same way: `test("description", () => {
...assertions... })`, using `assert`/`assertEqual` from the runner already in `app_test.html`.

## Verifying a new test actually has teeth

A passing test that was never confirmed to fail against the bug it targets proves nothing (this
is exactly how the syntax error this file exists to catch shipped in the first place: it was
"verified live" without the reviewer thinking to break it first). Before trusting a new test:
temporarily reintroduce the bug it targets, confirm the harness goes red with the expected
error, then restore the fix and confirm green again. `git diff --stat` after restoring should be
empty for `app.js` -- if it isn't, the "fix" didn't round-trip back to the committed version.
