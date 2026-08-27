"""Read-through snapshot cache for Slice 2 enrichment lookups.

No fetchers live here — this module only knows how to check
`data/snapshots/` for a previously cached response, hand control to the
caller's fetch function on a miss (unless offline mode forbids it), and
persist whatever comes back with a source identifier and retrieval
timestamp attached. `nvd.py`, `kev.py`, `epss.py`, and `attack.py` are
callers of `SnapshotCache`, not part of it.

Path layout mirrors CLAUDE.md's repository layout: a source queried with
no key (KEV membership, the EPSS bulk feed — one file covers every CVE)
lands at `<source>.json`; a source queried with a key (NVD per-CVE
records, ATT&CK bundles) lands at `<source>/<key>.json`.

Per CLAUDE.md Section 8 rule 4, writing over an existing snapshot always
bumps its version rather than silently overwriting it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SNAPSHOT_DIR = REPO_ROOT / "data" / "snapshots"

# CVE IDs, ATT&CK bundle/technique names, and similar keys are all plain
# identifiers. Restricting to this set keeps a key from ever escaping its
# source's directory (no "/", no "..").
_SAFE_KEY = re.compile(r"^[A-Za-z0-9._-]+$")


class OfflineCacheMissError(RuntimeError):
    """Raised when offline mode is on and no snapshot exists for a lookup.

    Offline mode exists to fail loudly here rather than silently reaching
    the network, so this is never caught and retried automatically.
    """


class SnapshotError(RuntimeError):
    """Raised when a snapshot file on disk is missing a required field."""


def _validate_key(key: str) -> None:
    if not _SAFE_KEY.match(key):
        raise ValueError(f"unsafe snapshot key: {key!r}")


@dataclass(frozen=True)
class SnapshotEntry:
    source: str
    key: str | None
    version: int
    retrieved_at: str
    payload: Any

    def to_json(self) -> dict:
        return {
            "source": self.source,
            "key": self.key,
            "version": self.version,
            "retrieved_at": self.retrieved_at,
            "payload": self.payload,
        }

    @classmethod
    def from_json(cls, data: dict) -> SnapshotEntry:
        try:
            return cls(
                source=data["source"],
                key=data.get("key"),
                version=data["version"],
                retrieved_at=data["retrieved_at"],
                payload=data["payload"],
            )
        except KeyError as exc:
            raise SnapshotError(f"snapshot missing required field: {exc}") from exc


class SnapshotCache:
    """Read-through cache backed by JSON files under a snapshot directory."""

    def __init__(self, snapshot_dir: Path | None = None, *, offline: bool = False):
        self.snapshot_dir = snapshot_dir or DEFAULT_SNAPSHOT_DIR
        self.offline = offline

    def _path(self, source: str, key: str | None) -> Path:
        if key is None:
            return self.snapshot_dir / f"{source}.json"
        _validate_key(key)
        return self.snapshot_dir / source / f"{key}.json"

    def read(self, source: str, key: str | None = None) -> SnapshotEntry | None:
        path = self._path(source, key)
        if not path.exists():
            return None
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return SnapshotEntry.from_json(data)

    def write(self, source: str, key: str | None, payload: Any) -> SnapshotEntry:
        """Persist `payload`, bumping the version if a snapshot already
        exists at this source/key rather than overwriting it silently."""
        existing = self.read(source, key)
        version = existing.version + 1 if existing is not None else 1
        entry = SnapshotEntry(
            source=source,
            key=key,
            version=version,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            payload=payload,
        )
        path = self._path(source, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_name(path.name + ".tmp")
        with tmp_path.open("w", encoding="utf-8") as f:
            json.dump(entry.to_json(), f, indent=2, sort_keys=True)
            f.write("\n")
        tmp_path.replace(path)
        return entry

    def get_or_fetch(
        self, source: str, key: str | None, fetch: Callable[[], Any]
    ) -> SnapshotEntry:
        """Check the snapshot first; call `fetch` only on a miss.

        A hit is returned as-is regardless of offline mode — offline only
        governs whether a *miss* is allowed to reach the network. On a
        miss in offline mode, this raises `OfflineCacheMissError` instead
        of calling `fetch`.
        """
        cached = self.read(source, key)
        if cached is not None:
            return cached
        if self.offline:
            where = source if key is None else f"{source}:{key}"
            raise OfflineCacheMissError(
                f"--offline forbids network access and no snapshot exists for {where}"
            )
        payload = fetch()
        return self.write(source, key, payload)
