"""Read-only-by-default FastAPI viewer for one `rhino run --export` JSON
file (export.py's EXPORT_SCHEMA_VERSION contract). Launched via `rhino web
--export PATH [--port PORT]` (cli.py).

**The one and only data access this module makes, by default, is reading a
file off disk.** No route here imports `rhinosecure.cli`, `rhinosecure.
agents.*`, `rhinosecure.memory`, or `crewai` **at module level** -- there is
nothing this module's own top-level imports can start a pipeline run,
dispatch an agent, make an LLM call, or write to memory.py's SQLite
database. Every request against `/api/export` re-reads the export file
fresh off disk (no in-process cache), so a regenerated export shows up on
the next browser refresh without restarting the server -- still a pure
read, never a write, and never anything that recomputes what the file says.

**`jobs_enabled` and `chat_enabled` are the two, explicit, opt-in
exceptions -- and both are structural, not a permission check.**
`create_app(jobs_enabled=True, job_config=...)` is the only way
`rhinosecure.web.jobs` (the write-capable job substrate -- constraint
submission, ingest proposal, deterministic/agent runs, and remediation
marking, all as background jobs with progress polling), `rhinosecure.web
.uploads` (filesystem-only upload mechanics for the conversational front
end -- never a job, never `PlanState`/`Coordinator`/`Memory`, see that
module's own docstring), `rhinosecure.web.route` (the Router dispatcher --
wires `agents/router.py` into the two modules above; never a THIRD way to
run a job, only a second way to ask for one, gated per step by a human's
own approval click), and `rhinosecure.web.adapters` (read-only proposal
inspection plus the dedicated, non-Router-reachable confirmation gate --
see that module's own docstring for why it is a separate surface from
`ingest_propose` rather than a new Router operation) are ever imported,
and `create_app(chat_enabled=True)` is the only way `rhinosecure.web.chat`
(read-only, LLM-backed Q&A over the currently-served export -- never a
write, never memory.py or agents.coordinator) is ever imported. All five
imports happen *inside* `create_app`'s own body, conditionally -- never at
this module's top level. `create_app()` (the default: both flags `False`)
never imports any of them and never mounts `POST /api/jobs`, `POST
/api/uploads`, `POST /api/route`, `POST /api/chat`, or anything under
`/api/adapters`; a request to any of those routes against a default app is
a plain 404 (the route was never registered), not a route that exists and
refuses. `rhino web`'s `--enable-jobs`/`--enable-chat` flags are the only
things that can turn these on, independently of each other -- see
`web/jobs.py`'s, `web/uploads.py`'s, `web/route.py`'s, `web/adapters.py`'s,
and `web/chat.py`'s own module docstrings for what each does once enabled.

**One export file per server process.** The file path is resolved once,
at `create_app()` time, from (in order) an explicit `export_path`
argument, the `RHINOSECURE_EXPORT_PATH` environment variable, or
`DEFAULT_EXPORT_PATH` (`out/export_web.json` under the repo root --
deliberately NOT `out/export_demo.json`: the conversational front end's
empty-workspace design means a fresh `rhino web` must open empty even on
a checkout where `rhino run --data demo --export out/export_demo.json`
has already been run for testing -- the demo fixture stays a frozen test
artifact, not what the app happens to show on launch just because that
file exists on disk). It is not re-resolved per request and cannot be
changed by any request --
there is no route that accepts a path from a client, so nothing served
here can be pointed at an arbitrary file by a browser. A missing or
unreadable file is a 404/500 on `/api/export`, not a startup failure: the
server should come up (and the frontend should render its honest empty
states) even before a real export exists at that path. When jobs are
enabled, this is also the one path the job substrate writes to after a
successful constraint submission -- `web/jobs.py`'s `PlanState` is handed
this exact resolved path, never a second, independently-configured one.

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
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

if TYPE_CHECKING:  # never imported at runtime unless jobs_enabled=True -- see create_app
    from rhinosecure.web.jobs import JobConfig

_WEB_DIR = Path(__file__).resolve().parent
_STATIC_DIR = _WEB_DIR / "static"
_REPO_ROOT = _WEB_DIR.parents[2]  # .../web -> rhinosecure -> src -> repo root

EXPORT_PATH_ENV = "RHINOSECURE_EXPORT_PATH"
DEFAULT_EXPORT_PATH = _REPO_ROOT / "out" / "export_web.json"


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


def load_export(path: Path) -> Any:
    """Read and parse `path` fresh off disk -- the server's only data
    access, and (unprefixed, unlike this module's other helpers) the one
    piece of it `web/chat.py` also calls, so a chat answer and `GET
    /api/export` can never read two different copies of the same file.
    Raises `HTTPException` (never a bare exception) so FastAPI turns a
    missing or corrupt export file into a real, informative HTTP error
    instead of an unhandled-exception 500."""
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


def create_app(
    export_path: Path | str | None = None,
    *,
    jobs_enabled: bool = False,
    job_config: "JobConfig | None" = None,
    chat_enabled: bool = False,
) -> FastAPI:
    """Build the FastAPI app for one export file. `export_path` overrides
    the environment variable and the default (see module docstring for
    the resolution order). The resolved path is stashed on
    `app.state.export_path` so a caller (cli.py's `rhino web`) can print
    exactly what's being served without re-deriving the same logic.

    `jobs_enabled=False`/`chat_enabled=False` (both default) mount no new
    routes and import `rhinosecure.web.jobs`/`rhinosecure.web.uploads`/
    `rhinosecure.web.route`/`rhinosecure.web.adapters`/`rhinosecure.web
    .chat` not at all -- the two existing GET routes and static serving are
    unchanged; `/api/health`'s response gains two fields (`"jobs_enabled"`,
    `"chat_enabled"`, both `false`) so a frontend can tell whether to show
    constraint-submission/upload/route or chat UI at all, without a route
    it would need to probe with a POST. `jobs_enabled=True` requires
    `job_config` (a `web.jobs.JobConfig`) and additionally mounts
    `POST /api/jobs`, `GET /api/jobs/{id}`, `GET /api/jobs`;
    (from `web/uploads.py`) `POST /api/uploads`, `GET /api/uploads/{id}`,
    `POST /api/uploads/{id}/label`; (from `web/route.py`)
    `POST /api/route`, `GET /api/route/{id}`, `GET /api/route`,
    `POST /api/route/{id}/steps/{index}/approve`,
    `POST /api/route/{id}/steps/{index}`; and (from `web/adapters.py`)
    `GET /api/adapters/{name}/proposal`, `GET /api/adapters/{name}/review`,
    `POST /api/adapters/{name}/confirm` -- uploads, routing, and adapter
    inspection/confirmation all ride on the same flag rather than their
    own, since none has a purpose without the job substrate they read from
    or dispatch into (`web/uploads.py`'s, `web/route.py`'s, and
    `web/adapters.py`'s own module docstrings). `chat_enabled=True` needs no
    config object -- chat has nothing to seed, see `web/chat.py`'s module
    docstring -- and additionally mounts `POST /api/chat`, plus makes
    `qa_question` a Router-selectable operation when jobs are ALSO
    enabled (`web/route.py`'s `_registered_ops`). The two flags are
    independent; either, both, or neither may be set."""
    resolved = _resolve_export_path(export_path)

    app = FastAPI(title="RhinoSecure Plan Viewer", docs_url=None, redoc_url=None)
    app.state.export_path = resolved

    @app.get("/api/export")
    def get_export() -> Any:
        return load_export(app.state.export_path)

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        path = app.state.export_path
        return {
            "status": "ok",
            "export_filename": path.name,
            "export_exists": path.exists(),
            "jobs_enabled": jobs_enabled,
            "chat_enabled": chat_enabled,
        }

    if jobs_enabled:
        if job_config is None:
            raise ValueError("create_app(jobs_enabled=True) requires job_config=")
        from rhinosecure.web.adapters import mount_adapter_routes
        from rhinosecure.web.jobs import mount_job_routes
        from rhinosecure.web.route import mount_route_routes
        from rhinosecure.web.uploads import mount_upload_routes

        mount_job_routes(app, job_config)
        mount_upload_routes(app)
        # mount_route_routes/mount_adapter_routes read app.state.job_registry/
        # plan_state/upload_registry back off what the two calls above just
        # set -- both must run after both, never before.
        mount_route_routes(app, chat_enabled=chat_enabled)
        mount_adapter_routes(app)

    if chat_enabled:
        from rhinosecure.web.chat import mount_chat_routes

        mount_chat_routes(app)

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
