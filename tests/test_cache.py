import json
from pathlib import Path

import pytest

from rhinosecure.enrich.cache import (
    OfflineCacheMissError,
    SnapshotCache,
    SnapshotError,
)


def test_miss_calls_fetch_and_writes_snapshot(tmp_path: Path):
    cache = SnapshotCache(tmp_path)
    calls = []

    def fetch():
        calls.append(1)
        return {"cvss": 9.8}

    entry = cache.get_or_fetch("nvd", "CVE-2021-26855", fetch)

    assert calls == [1]
    assert entry.payload == {"cvss": 9.8}
    assert entry.source == "nvd"
    assert entry.key == "CVE-2021-26855"
    assert entry.version == 1
    assert entry.retrieved_at  # non-empty timestamp recorded


def test_hit_does_not_call_fetch(tmp_path: Path):
    cache = SnapshotCache(tmp_path)
    cache.write("kev", None, {"known_exploited": True})

    def fetch():
        raise AssertionError("fetch must not be called on a cache hit")

    entry = cache.get_or_fetch("kev", None, fetch)
    assert entry.payload == {"known_exploited": True}


def test_offline_hit_still_returns_cached_entry_without_fetching(tmp_path: Path):
    cache = SnapshotCache(tmp_path, offline=True)
    cache.write("epss", None, {"score": 0.42})

    def fetch():
        raise AssertionError("fetch must not be called even in offline mode on a hit")

    entry = cache.get_or_fetch("epss", None, fetch)
    assert entry.payload == {"score": 0.42}


def test_offline_miss_raises_and_does_not_fetch(tmp_path: Path):
    cache = SnapshotCache(tmp_path, offline=True)

    def fetch():
        raise AssertionError("fetch must not be called when offline forbids it")

    with pytest.raises(OfflineCacheMissError):
        cache.get_or_fetch("nvd", "CVE-2020-1472", fetch)


def test_write_bumps_version_instead_of_overwriting(tmp_path: Path):
    cache = SnapshotCache(tmp_path)
    first = cache.write("kev", None, {"n": 1})
    second = cache.write("kev", None, {"n": 2})

    assert first.version == 1
    assert second.version == 2
    # the on-disk file reflects the latest write, version bumped
    on_disk = cache.read("kev", None)
    assert on_disk.version == 2
    assert on_disk.payload == {"n": 2}


def test_no_key_path_is_source_dot_json(tmp_path: Path):
    cache = SnapshotCache(tmp_path)
    cache.write("kev", None, {"a": 1})
    assert (tmp_path / "kev.json").exists()


def test_keyed_path_is_source_dir_slash_key_dot_json(tmp_path: Path):
    cache = SnapshotCache(tmp_path)
    cache.write("nvd", "CVE-2021-26855", {"a": 1})
    assert (tmp_path / "nvd" / "CVE-2021-26855.json").exists()


def test_unsafe_key_is_rejected(tmp_path: Path):
    cache = SnapshotCache(tmp_path)
    with pytest.raises(ValueError):
        cache.write("nvd", "../../etc/passwd", {"a": 1})


def test_snapshot_records_source_and_timestamp_on_disk(tmp_path: Path):
    cache = SnapshotCache(tmp_path)
    cache.write("attack", "enterprise-attack", {"techniques": []})

    raw = json.loads((tmp_path / "attack" / "enterprise-attack.json").read_text())
    assert raw["source"] == "attack"
    assert raw["key"] == "enterprise-attack"
    assert "retrieved_at" in raw and raw["retrieved_at"]
    assert raw["version"] == 1


def test_read_missing_snapshot_returns_none(tmp_path: Path):
    cache = SnapshotCache(tmp_path)
    assert cache.read("nvd", "CVE-9999-0001") is None


def test_read_malformed_snapshot_raises_snapshot_error(tmp_path: Path):
    path = tmp_path / "kev.json"
    path.write_text(json.dumps({"source": "kev"}))  # missing required fields

    cache = SnapshotCache(tmp_path)
    with pytest.raises(SnapshotError):
        cache.read("kev", None)


def test_default_snapshot_dir_matches_repo_layout():
    from rhinosecure.enrich.cache import DEFAULT_SNAPSHOT_DIR

    assert DEFAULT_SNAPSHOT_DIR.name == "snapshots"
    assert DEFAULT_SNAPSHOT_DIR.parent.name == "data"
