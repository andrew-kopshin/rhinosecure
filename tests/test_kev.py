from pathlib import Path

import pytest

from rhinosecure.enrich.cache import OfflineCacheMissError, SnapshotCache
from rhinosecure.enrich.kev import KEV_URL, load_catalog

FAKE_CATALOG = {
    "catalogVersion": "2026.08.27",
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-26855",
            "vendorProject": "Microsoft",
            "product": "Exchange Server",
            "vulnerabilityName": "ProxyLogon",
            "dateAdded": "2021-11-03",
            "dueDate": "2021-11-17",
            "requiredAction": "Apply updates per vendor instructions.",
        }
    ],
}


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def test_listed_cve_returns_listed_status_with_dates(tmp_path: Path):
    cache = SnapshotCache(tmp_path)
    cache.write("kev", None, FAKE_CATALOG)

    catalog = load_catalog(cache)
    status = catalog.status("CVE-2021-26855")

    assert status.is_listed is True
    assert status.date_added == "2021-11-03"
    assert status.due_date == "2021-11-17"


def test_unlisted_cve_returns_not_listed_with_no_dates(tmp_path: Path):
    cache = SnapshotCache(tmp_path)
    cache.write("kev", None, FAKE_CATALOG)

    catalog = load_catalog(cache)
    status = catalog.status("CVE-9999-99999")

    assert status.is_listed is False
    assert status.date_added is None
    assert status.due_date is None


def test_online_miss_fetches_via_requests_and_caches(tmp_path: Path, monkeypatch):
    calls = []

    def fake_get(url, timeout):
        calls.append((url, timeout))
        return _FakeResponse(FAKE_CATALOG)

    monkeypatch.setattr("rhinosecure.enrich.kev.requests.get", fake_get)

    cache = SnapshotCache(tmp_path)
    catalog = load_catalog(cache)

    assert calls == [(KEV_URL, 30)]
    assert catalog.status("CVE-2021-26855").is_listed is True
    # second load must hit the snapshot, not fetch again
    calls.clear()
    load_catalog(cache)
    assert calls == []


def test_offline_hit_loads_from_snapshot_without_network(tmp_path: Path, monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("requests.get must not be called on an offline hit")

    monkeypatch.setattr("rhinosecure.enrich.kev.requests.get", fail_if_called)

    cache = SnapshotCache(tmp_path, offline=True)
    cache.write("kev", None, FAKE_CATALOG)

    catalog = load_catalog(cache)
    assert catalog.status("CVE-2021-26855").is_listed is True


def test_offline_miss_raises_without_network(tmp_path: Path, monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("requests.get must not be called on an offline miss")

    monkeypatch.setattr("rhinosecure.enrich.kev.requests.get", fail_if_called)

    cache = SnapshotCache(tmp_path, offline=True)
    with pytest.raises(OfflineCacheMissError):
        load_catalog(cache)
