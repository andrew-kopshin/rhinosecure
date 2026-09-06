"""Upload mechanics for the conversational front end -- CLAUDE.md's
"Future direction: a conversational front end", section 1. The third
module `web/server.py` is allowed to reach for beyond serving a static
export file (alongside `web/jobs.py`/`web/chat.py`), mounted only when
`create_app(jobs_enabled=True, ...)` -- "an upload with nothing to ingest
it has no purpose on a chat-only deployment" (the design's own wording).
`create_app()` imports this module only inside its own body, in the same
`if jobs_enabled:` branch that already imports `web/jobs.py` -- never at
`web/server.py`'s module level, the same import-boundary discipline every
other opt-in module here already follows.

**A filesystem operation, not a job.** Nothing in this module touches
`PlanState`/`Coordinator`/`Memory`, imports `rhinosecure.agents`,
`rhinosecure.ingest`, or `crewai`, or goes through `JobRegistry` -- an
upload competes for none of `JobRegistry`'s single in-flight slot, and
completes synchronously within its own HTTP request (the same "regular,
not background" shape `web/chat.py`'s route already has, for the same
reason: there is no shared mutable state here for two concurrent uploads
to race on beyond this module's own lock-guarded registry).

**The load-bearing decision: an upload directory is structurally nothing
but another `--data` directory.** Files land under `data/uploads/
<upload_id>/<sanitized-original-filename>` -- the exact same `data/<name>/
{assets,findings}.csv`-shaped layout `ingest.load_batch`/every adapter's
own validation already expects, so a later slice (the confirmation gate,
`schema_inference.propose_contract`, or a plain `--data uploads/<id>`)
needs no new ingest code path at all. This module's only job is getting
bytes onto disk in that shape -- it does not read, validate, or interpret
their contents in any way.

**`upload_id = uuid.uuid4().hex`, never content-derived.** Two different
uploads of byte-identical files (trivially, the demo fixture, uploaded by
two different people) would otherwise silently share one directory with
no session scoping -- an id has to name a SESSION, not a payload.
Retry-safety for a dropped connection is the standard `Idempotency-Key`
header instead (see `UploadRegistry.cached_response`/`cache_response`):
a client's response arriving as a network error after the server actually
finished must not manufacture a second orphan `upload_id` on retry.

**Sanitization takes `Path(original_filename).name` only** -- discarding
any client-claimed directory component (`../../etc/passwd`, a bare
absolute path) before it ever reaches a filesystem call. The remaining
name is used exactly as given, never renamed to match a built-in format's
expected filename: a later slice's "does this already look like a known
format" check (CLAUDE.md's confirmation-gate section) depends on seeing
the name the source actually shipped with.

**Streaming, with a hard ceiling enforced mid-stream, not after.**
`await file.read()` with no bound is exactly the "assumes the dataset is
small enough to hold in memory" shape CLAUDE.md Section 1 names as a
defect at fleet scale, made concrete for upload bytes rather than CSV
rows. `_write_upload` reads in `_CHUNK_SIZE`-byte pieces, writes them to a
`.part` file, and aborts -- deleting the partial file, never leaving one
behind -- the instant the running total exceeds `RHINO_MAX_UPLOAD_BYTES`,
before the rest of the body is even read off the wire. The `.part` file is
atomically renamed to its final sanitized name only on a clean finish
(`Path.replace`, the same atomic-rename convention `export.py`'s
`_write_json_atomic` already uses for its own reason -- a concurrent
reader must see either nothing or the complete file, never a partial one).

**Single- vs. two-file sources are never inferred.** A set of one file is
a BluePeak-shaped single-file candidate and is `ready` the moment it
lands -- there is no second role for it to be confused with. A set of two
requires an explicit human label per file (`"inventory"` / `"findings"`,
`VALID_LABELS`) before it's `ready`: a wrong guess here would corrupt
everything downstream with no `check_grounding`-shaped mechanism able to
catch a plausible-but-wrong file-role assignment the way one catches a
bad column mapping (the design's own reasoning, verbatim). A third file
is refused outright -- this project has no format shaped like anything
past two files, and accepting one silently would just delay the same
refusal to whatever reads the directory next, with a worse error message.

**Bounded, but no disk lifecycle -- a known limitation, not a silent
gap.** `UploadRegistry` bounds its own in-memory bookkeeping the same way
`web/jobs.py`'s `JobRegistry` bounds job history, but evicting a set's
*record* here does not delete its *directory* -- unlike a `Job`, an
upload set's entire reason to exist is the files it wrote to disk, which
a later slice (propose/confirm, a run) may still need to read well after
this module has forgotten about it in memory. Real disk garbage
collection (a TTL, an explicit delete route, cleanup on server restart)
is deliberately not built here; flagged so it isn't assumed done by
omission, the same convention CLAUDE.md itself uses for its own open
items.
"""

from __future__ import annotations

import os
import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile
from pydantic import BaseModel

_WEB_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _WEB_DIR.parents[2]  # .../web -> rhinosecure -> src -> repo root
DEFAULT_UPLOADS_DIR = _REPO_ROOT / "data" / "uploads"

MAX_UPLOAD_BYTES_ENV = "RHINO_MAX_UPLOAD_BYTES"
DEFAULT_MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MiB -- generous for a CSV export, not unbounded
_CHUNK_SIZE = 1024 * 1024  # 1 MiB, per the design's own streaming spec

MAX_FILES_PER_UPLOAD_SET = 2  # single_file (self-describing) or two_file (inventory + findings); never more
MAX_UPLOAD_SETS_TRACKED = 200  # bounded in-memory history, mirrors web/jobs.py's MAX_JOB_HISTORY
MAX_IDEMPOTENCY_KEYS_TRACKED = 200

VALID_LABELS = frozenset({"inventory", "findings"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _max_upload_bytes() -> int:
    raw = os.environ.get(MAX_UPLOAD_BYTES_ENV)
    if not raw:
        return DEFAULT_MAX_UPLOAD_BYTES
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_UPLOAD_BYTES
    return value if value > 0 else DEFAULT_MAX_UPLOAD_BYTES


class UploadTooLargeError(Exception):
    """Raised mid-stream by `_write_upload` once the running total exceeds
    the configured ceiling. Never reaches a caller as a bare exception --
    the route below turns it into HTTPException(413)."""

    def __init__(self, limit: int):
        self.limit = limit
        super().__init__(f"upload exceeds the {limit}-byte limit")


@dataclass
class UploadedFile:
    filename: str
    size: int
    label: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"filename": self.filename, "size": self.size, "label": self.label}


@dataclass
class UploadSet:
    """One upload session: an id, the directory its files actually live
    in, and the label each file carries (if any). `layout`/`ready` are
    computed, never stored, so they can never drift from the files dict
    they're derived from -- the same "never store what a read can
    recompute" instinct `memory.Memory`'s own `contested_pct` property
    already follows."""

    id: str
    dir_path: Path
    created_at: str = field(default_factory=_now)
    files: "OrderedDict[str, UploadedFile]" = field(default_factory=OrderedDict)

    @property
    def layout(self) -> str:
        if not self.files:
            return "empty"
        return "single_file" if len(self.files) == 1 else "two_file"

    @property
    def ready(self) -> bool:
        if len(self.files) == 1:
            return True
        if len(self.files) == 2:
            return {f.label for f in self.files.values()} == VALID_LABELS
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "upload_id": self.id,
            "created_at": self.created_at,
            "relative_data_dir": f"uploads/{self.id}",
            "files": [f.to_dict() for f in self.files.values()],
            "layout": self.layout,
            "ready": self.ready,
        }


class UploadRegistry:
    """In-memory, bounded upload-set bookkeeping plus an idempotency-key
    cache -- mirrors `web/jobs.py`'s `JobRegistry` shape (one lock, one
    long-lived registry, no per-field atomicity assumptions), for the same
    reason: an `UploadSet`'s fields can be written and read from different
    request-handling threads."""

    def __init__(self, base_dir: Path, *, max_sets: int = MAX_UPLOAD_SETS_TRACKED):
        self._lock = threading.Lock()
        self._base_dir = base_dir
        self._sets: OrderedDict[str, UploadSet] = OrderedDict()
        self._max_sets = max_sets
        self._idempotency: OrderedDict[str, dict[str, Any]] = OrderedDict()

    def create_set(self) -> UploadSet:
        with self._lock:
            upload_id = uuid.uuid4().hex
            dir_path = self._base_dir / upload_id
            dir_path.mkdir(parents=True, exist_ok=True)
            upload_set = UploadSet(id=upload_id, dir_path=dir_path)
            self._sets[upload_id] = upload_set
            while len(self._sets) > self._max_sets:
                # Evicts the in-memory RECORD only -- see module docstring's
                # "no disk lifecycle" note. The directory this set wrote to
                # is untouched.
                self._sets.popitem(last=False)
            return upload_set

    def get(self, upload_id: str) -> UploadSet | None:
        with self._lock:
            return self._sets.get(upload_id)

    def list_recent(self) -> list[dict[str, Any]]:
        """Every currently-tracked upload set, newest last -- what
        `web/route.py` reads to tell the Router which `upload_id`(s) are
        real right now (grounding's `known_upload_ids`) and to build a
        human-readable context note, so the model doesn't have to be told
        an upload_id by the human typing a 32-character hex string."""
        with self._lock:
            return [s.to_dict() for s in self._sets.values()]

    def record_file(self, upload_id: str, filename: str, size: int) -> dict[str, Any]:
        """Adds (or overwrites) one file's entry. Overwriting resets any
        prior label to None -- a label is a human's claim about a
        specific file's ROLE, and the file's content just changed, so
        carrying the old label forward would be exactly the kind of
        stale, unverified claim this project's not_collected/refuse-
        rather-than-guess discipline exists to avoid elsewhere."""
        with self._lock:
            upload_set = self._sets.get(upload_id)
            if upload_set is None:
                raise KeyError(upload_id)
            upload_set.files[filename] = UploadedFile(filename=filename, size=size, label=None)
            upload_set.files.move_to_end(filename)
            return upload_set.to_dict()

    def set_label(self, upload_id: str, filename: str, label: str) -> dict[str, Any]:
        with self._lock:
            upload_set = self._sets.get(upload_id)
            if upload_set is None:
                raise KeyError(upload_id)
            uploaded = upload_set.files.get(filename)
            if uploaded is None:
                raise LookupError(filename)
            other_labels = {f.label for name, f in upload_set.files.items() if name != filename}
            if label in other_labels:
                raise ValueError(
                    f"{label!r} is already assigned to another file in this set -- each of the two "
                    "roles applies to exactly one file"
                )
            uploaded.label = label
            return upload_set.to_dict()

    def cached_response(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            return self._idempotency.get(key)

    def cache_response(self, key: str, response: dict[str, Any]) -> None:
        with self._lock:
            self._idempotency[key] = response
            self._idempotency.move_to_end(key)
            while len(self._idempotency) > MAX_IDEMPOTENCY_KEYS_TRACKED:
                self._idempotency.popitem(last=False)


async def _write_upload(upload_file: UploadFile, dest_dir: Path, filename: str, max_bytes: int) -> int:
    """Streams `upload_file` to `dest_dir/filename` in `_CHUNK_SIZE`
    pieces via a `.part` intermediate, atomically renamed on a clean
    finish. Raises `UploadTooLargeError` -- deleting the partial file
    first -- the instant the running total exceeds `max_bytes`, without
    reading the rest of the body."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    part_path = dest_dir / f"{filename}.part"
    final_path = dest_dir / filename
    total = 0
    try:
        with part_path.open("wb") as out:
            while True:
                chunk = await upload_file.read(_CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise UploadTooLargeError(max_bytes)
                out.write(chunk)
    except UploadTooLargeError:
        part_path.unlink(missing_ok=True)
        raise
    except BaseException:
        part_path.unlink(missing_ok=True)
        raise
    part_path.replace(final_path)
    return total


class LabelRequest(BaseModel):
    filename: str
    label: str


def mount_upload_routes(app: FastAPI, uploads_dir: Path | None = None) -> None:
    """Called by `create_app()` only when `jobs_enabled=True` -- see
    module docstring. `uploads_dir` defaults to `data/uploads` under the
    repo root, matching every `--data <name>` directory's own home
    (`cli.py`'s `REPO_ROOT / "data" / data_arg`); overridable so tests
    don't write into the real repo tree."""
    registry = UploadRegistry(uploads_dir or DEFAULT_UPLOADS_DIR)
    app.state.upload_registry = registry

    @app.post("/api/uploads", status_code=201)
    async def post_upload(
        file: UploadFile = File(...),
        upload_id: str | None = Form(None),
        label: str | None = Form(None),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        if idempotency_key:
            cached = registry.cached_response(idempotency_key)
            if cached is not None:
                return cached

        sanitized = Path(file.filename or "").name
        if not sanitized or sanitized in (".", ".."):
            # Path(...).name strips directory components but does NOT
            # neutralize a bare "." or ".." -- Path("..").name == ".."
            # itself, verified directly (not assumed), which combined with
            # dest_dir / sanitized would resolve one level UP from the
            # upload directory, a real path-escape rather than a merely
            # odd filename. Checked explicitly since sanitization alone
            # does not close this.
            raise HTTPException(400, f"{file.filename!r} is not a usable filename")

        if upload_id is None:
            upload_set = registry.create_set()
        else:
            upload_set = registry.get(upload_id)
            if upload_set is None:
                raise HTTPException(404, f"no such upload set: {upload_id!r}")

        if label is not None and label not in VALID_LABELS:
            raise HTTPException(400, f"label must be one of {sorted(VALID_LABELS)}, got {label!r}")

        if sanitized not in upload_set.files and len(upload_set.files) >= MAX_FILES_PER_UPLOAD_SET:
            raise HTTPException(
                400,
                f"this upload set already has {MAX_FILES_PER_UPLOAD_SET} file(s) "
                f"({', '.join(upload_set.files)}) -- a source is at most one file (self-describing) "
                "or two (an inventory file and a findings file, each labeled), never inferred beyond that",
            )

        max_bytes = _max_upload_bytes()
        try:
            size = await _write_upload(file, upload_set.dir_path, sanitized, max_bytes)
        except UploadTooLargeError:
            raise HTTPException(
                413, f"{sanitized!r} exceeds the {max_bytes}-byte upload limit ({MAX_UPLOAD_BYTES_ENV})"
            )
        except OSError as exc:
            # A sanitized name that still isn't a legal filename on this
            # filesystem (illegal characters, a reserved device name on
            # Windows, and similar) -- caught here rather than left to
            # surface as an unhandled 500, the same "refuse loudly with a
            # named reason" instinct as everywhere else this file refuses.
            raise HTTPException(400, f"{sanitized!r} is not a usable filename: {exc}")

        try:
            response = registry.record_file(upload_set.id, sanitized, size)
            if label is not None:
                response = registry.set_label(upload_set.id, sanitized, label)
        except KeyError:
            raise HTTPException(404, f"no such upload set: {upload_set.id!r}")
        except ValueError as exc:
            raise HTTPException(400, str(exc))

        if idempotency_key:
            registry.cache_response(idempotency_key, response)
        return response

    @app.get("/api/uploads/{upload_id}")
    def get_upload(upload_id: str) -> dict[str, Any]:
        upload_set = registry.get(upload_id)
        if upload_set is None:
            raise HTTPException(404, f"no such upload set: {upload_id!r}")
        return upload_set.to_dict()

    @app.post("/api/uploads/{upload_id}/label")
    def post_label(upload_id: str, body: LabelRequest) -> dict[str, Any]:
        if body.label not in VALID_LABELS:
            raise HTTPException(400, f"label must be one of {sorted(VALID_LABELS)}, got {body.label!r}")
        try:
            return registry.set_label(upload_id, body.filename, body.label)
        except KeyError:
            raise HTTPException(404, f"no such upload set: {upload_id!r}")
        except LookupError:
            raise HTTPException(404, f"no such file {body.filename!r} in upload set {upload_id!r}")
        except ValueError as exc:
            raise HTTPException(400, str(exc))
