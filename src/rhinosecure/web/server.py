"""Read-only FastAPI viewer for one `rhino run --export` JSON file
(export.py's EXPORT_SCHEMA_VERSION contract) -- the web half of the export
feature. Launched via `rhino web --export PATH [--port PORT]` (cli.py).

**The one and only data access this module makes is reading a file off
disk.** No route here imports `rhinosecure.cli`, `rhinosecure.agents.*`,
`rhinosecure.memory`, or `crewai` -- there is nothing in this module that
can start a pipeline run, dispatch an agent, make an LLM call, or write to
memory.py's SQLite database. Every request against `/api/export` re-reads
the export file fresh off disk (no in-process cache), so a regenerated
export shows up on the next browser refresh without restarting the
server -- still a pure read, never a write, and never anything that
recomputes what the file says.

**One export file per server process.** The file path is resolved once,
at `create_app()` time, from (in order) an explicit `export_path`
argument, the `RHINOSECURE_EXPORT_PATH` environment variable, or
`DEFAULT_EXPORT_PATH` (`out/export_demo.json` under the repo root -- the
sample the export feature's own implementer report already generated). It
is not re-resolved per request and cannot be changed by any request --
there is no route that accepts a path from a client, so nothing served
here can be pointed at an arbitrary file by a browser. A missing or
unreadable file is a 404/500 on `/api/export`, not a startup failure: the
server should come up (and the frontend should render its honest empty
states) even before a real export exists at that path.

Static assets (`static/index.html`, `styles.css`, `app.js` -- vanilla JS,
no build step, no framework dependency) are served as-is; `/` serves
`index.html`. `/api/health` is a small liveness/debug endpoint reporting
which file is configured and whether it currently exists -- it does not
read or parse the file's contents.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

_WEB_DIR = Path(__file__).resolve().parent
_STATIC_DIR = _WEB_DIR / "static"
_REPO_ROOT = _WEB_DIR.parents[2]  # .../web -> rhinosecure -> src -> repo root

EXPORT_PATH_ENV = "RHINOSECURE_EXPORT_PATH"
DEFAULT_EXPORT_PATH = _REPO_ROOT / "out" / "export_demo.json"


def _resolve_export_path(export_path: Path | str | None) -> Path:
    """Explicit argument wins, then the environment variable, then the
    default -- the same precedence `--db`/`memory.DEFAULT_DB_PATH` already
    uses elsewhere in this codebase (cli.py)."""
    if export_path is not None:
        return Path(export_path)
    env_value = os.environ.get(EXPORT_PATH_ENV)
    if env_value:
        return Path(env_value)
    return DEFAULT_EXPORT_PATH


def _load_export(path: Path) -> Any:
    """Read and parse `path` fresh off disk -- the server's only data
    access. Raises `HTTPException` (never a bare exception) so FastAPI
    turns a missing or corrupt export file into a real, informative HTTP
    error instead of an unhandled-exception 500."""
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail=f"no export file at {path} -- run `rhino run --export {path}` first",
        )
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"could not read export file {path}: {exc}")

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail=f"export file {path} is not valid JSON: {exc}")


def create_app(export_path: Path | str | None = None) -> FastAPI:
    """Build the FastAPI app for one export file. `export_path` overrides
    the environment variable and the default (see module docstring for
    the resolution order). The resolved path is stashed on
    `app.state.export_path` so a caller (cli.py's `rhino web`) can print
    exactly what's being served without re-deriving the same logic."""
    resolved = _resolve_export_path(export_path)

    app = FastAPI(title="RhinoSecure Plan Viewer", docs_url=None, redoc_url=None)
    app.state.export_path = resolved

    @app.get("/api/export")
    def get_export() -> Any:
        return _load_export(app.state.export_path)

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        path = app.state.export_path
        return {
            "status": "ok",
            "export_filename": path.name,
            "export_exists": path.exists(),
        }

    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(_STATIC_DIR / "index.html")

    return app


# Importable directly for `uvicorn rhinosecure.web.server:app` -- resolves
# the export path from RHINOSECURE_EXPORT_PATH / DEFAULT_EXPORT_PATH only.
# `rhino web` (cli.py) does not use this module-level instance -- it calls
# create_app(args.export) itself so an explicit --export always wins.
app = create_app()
