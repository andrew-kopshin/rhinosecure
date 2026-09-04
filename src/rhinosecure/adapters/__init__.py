"""Ingest adapter registry -- `rhino run --format <name>` resolves here.

See adapters/base.py for what an adapter is and for the `not_collected`
representation every adapter uses for fields its source format lacks.

`get_adapter` resolves the three BUILT-IN, hand-written formats -- a
static, fixed set (tests/test_adapters.py:19-23 pins its exact members).
`load_config_adapter` is the other resolution path, for a declarative
ingest contract (adapters/config_model.py, adapters/configured.py): a
config is not in `FORMATS` and never will be -- it is resolved by name
(or path) at call time, not enumerated ahead of it, so the built-in
namespace stays environment-independent and this module's own `--format`
`choices=sorted(FORMATS)` (cli.py) never has to change to accommodate one.
"""

from __future__ import annotations

from pathlib import Path

from rhinosecure.adapters.base import (
    NOT_COLLECTED_DEFAULTS,
    ROLE_DEFAULT_BY_OS_CLASS,
    AdapterError,
    IngestAdapter,
)
from rhinosecure.adapters.bluepeak import BluePeakAdapter
from rhinosecure.adapters.defender import DefenderAdapter
from rhinosecure.adapters.native import NativeAdapter

DEFAULT_FORMAT = NativeAdapter.format

FORMATS: dict[str, type[IngestAdapter]] = {
    NativeAdapter.format: NativeAdapter,
    DefenderAdapter.format: DefenderAdapter,
    BluePeakAdapter.format: BluePeakAdapter,
}

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ADAPTER_CONFIG_DIR = REPO_ROOT / "data" / "adapters"


def get_adapter(name: str) -> IngestAdapter:
    try:
        return FORMATS[name]()
    except KeyError:
        raise AdapterError(f"unknown ingest format {name!r}; known formats: {sorted(FORMATS)}") from None


def _resolve_config_path(name_or_path: str, config_dir: Path | None) -> Path:
    """A bare name (no path separator, no `.json` suffix) resolves under
    `config_dir` (default `DEFAULT_ADAPTER_CONFIG_DIR`, `data/adapters/`);
    anything that already looks like a path -- absolute, has a directory
    component, or ends `.json` -- is used exactly as given. This is what
    lets `--adapter-config bluepeak-gen` and `--adapter-config
    ./scratch/my-contract.json` both work from the same flag."""
    candidate = Path(name_or_path)
    if candidate.is_absolute() or candidate.suffix == ".json" or len(candidate.parts) > 1:
        return candidate
    return (config_dir or DEFAULT_ADAPTER_CONFIG_DIR) / f"{name_or_path}.json"


def load_config_adapter(name_or_path: str, *, config_dir: Path | None = None) -> IngestAdapter:
    """Resolve `--adapter-config`'s value to a `ConfiguredAdapter`, ready
    to hand to `ingest.load_batch` exactly like `get_adapter`'s result.

    Every failure mode here -- the file doesn't exist, isn't valid JSON,
    doesn't match the contract shape, or isn't confirmed (or was hand-
    edited after confirmation) -- raises an `AdapterError`, so every
    existing `except IngestError` in cli.py already catches it with no new
    clause needed: `AdapterError` subclasses `IngestError`
    (adapters/base.py), and so does every error `config_model`/`config_io`
    raise (`ContractError`, itself an `AdapterError`). A structurally
    invalid contract raises pydantic's own `ValidationError` from
    `config_io.read_contract` -- NOT an `IngestError` on its own -- so it
    is caught and re-raised here rather than left to reach the CLI raw.

    Imports `config_io`/`configured`/`config_model` lazily: those modules
    import `FORMATS` from this package (to refuse a config `format` name
    that collides with a built-in), so importing them at THIS module's own
    top level would be circular -- this package has to finish defining
    `FORMATS` first, which only happens once `load_config_adapter` itself
    is called, well after `adapters/__init__.py` has finished executing.
    """
    from pydantic import ValidationError

    from rhinosecure.adapters.config_io import read_contract
    from rhinosecure.adapters.configured import ConfiguredAdapter

    path = _resolve_config_path(name_or_path, config_dir)
    if not path.is_file():
        raise AdapterError(
            f"adapter config {name_or_path!r} not found (looked for {path}). Configs are confirmed "
            f"contracts under {config_dir or DEFAULT_ADAPTER_CONFIG_DIR} (rhino adapt propose/confirm, "
            "a later command), or pass a path to one directly."
        )
    try:
        contract = read_contract(path)  # ContractIOError (an AdapterError) propagates as-is
    except ValidationError as exc:
        raise AdapterError(f"{path}: not a valid adapter config -- {exc}") from exc
    return ConfiguredAdapter(contract)


__all__ = [
    "DEFAULT_ADAPTER_CONFIG_DIR",
    "DEFAULT_FORMAT",
    "FORMATS",
    "NOT_COLLECTED_DEFAULTS",
    "REPO_ROOT",
    "ROLE_DEFAULT_BY_OS_CLASS",
    "AdapterError",
    "BluePeakAdapter",
    "DefenderAdapter",
    "IngestAdapter",
    "NativeAdapter",
    "get_adapter",
    "load_config_adapter",
]
