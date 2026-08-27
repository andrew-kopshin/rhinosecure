from pathlib import Path

import pytest

from rhinosecure.enrich.cache import OfflineCacheMissError, SnapshotCache
from rhinosecure.enrich.epss import EPSS_URL, lookup

SCORED_BODY = {
    "status": "OK",
    "status-code": 200,
    "total": 1,
    "data": [
        {
            "cve": "CVE-2021-26855",
            "epss": "0.944870000",
            "percentile": "0.999710000",
            "date": "2026-08-26",
        }
    ],
}

UNSCORED_BODY = {
    "status": "OK",
    "status-code": 200,
    "total": 0,
    "data": [],
}


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def test_scored_cve_returns_score_and_percentile(tmp_path: Path):
    cache = SnapshotCache(tmp_path)
    cache.write("epss", "CVE-2021-26855", SCORED_BODY)

    score = lookup("CVE-2021-26855", cache)

    assert score.is_scored is True
    assert score.score == pytest.approx(0.94487)
    assert score.percentile == pytest.approx(0.99971)
    assert score.score_date == "2026-08-26"


def test_unscored_cve_returns_none_fields(tmp_path: Path):
    cache = SnapshotCache(tmp_path)
    cache.write("epss", "CVE-0000-00000", UNSCORED_BODY)

    score = lookup("CVE-0000-00000", cache)

    assert score.is_scored is False
    assert score.score is None
    assert score.percentile is None
    assert score.score_date is None


def test_online_miss_fetches_via_requests_and_caches(tmp_path: Path, monkeypatch):
    calls = []

    def fake_get(url, params, timeout):
        calls.append((url, params, timeout))
        return _FakeResponse(SCORED_BODY)

    monkeypatch.setattr("rhinosecure.enrich.epss.requests.get", fake_get)

    cache = SnapshotCache(tmp_path)
    score = lookup("CVE-2021-26855", cache)

    assert calls == [(EPSS_URL, {"cve": "CVE-2021-26855"}, 30)]
    assert score.score == pytest.approx(0.94487)

    calls.clear()
    lookup("CVE-2021-26855", cache)
    assert calls == []  # second lookup must hit the snapshot, not fetch again


def test_offline_hit_loads_from_snapshot_without_network(tmp_path: Path, monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("requests.get must not be called on an offline hit")

    monkeypatch.setattr("rhinosecure.enrich.epss.requests.get", fail_if_called)

    cache = SnapshotCache(tmp_path, offline=True)
    cache.write("epss", "CVE-2021-26855", SCORED_BODY)

    score = lookup("CVE-2021-26855", cache)
    assert score.score == pytest.approx(0.94487)


def test_offline_miss_raises_without_network(tmp_path: Path, monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("requests.get must not be called on an offline miss")

    monkeypatch.setattr("rhinosecure.enrich.epss.requests.get", fail_if_called)

    cache = SnapshotCache(tmp_path, offline=True)
    with pytest.raises(OfflineCacheMissError):
        lookup("CVE-2021-26855", cache)


def test_each_cve_cached_under_its_own_key(tmp_path: Path):
    cache = SnapshotCache(tmp_path)
    cache.write("epss", "CVE-2021-26855", SCORED_BODY)
    assert (tmp_path / "epss" / "CVE-2021-26855.json").exists()
