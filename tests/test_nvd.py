from pathlib import Path

import pytest
import requests

from rhinosecure.enrich.cache import OfflineCacheMissError, SnapshotCache
from rhinosecure.enrich.nvd import NVD_URL, lookup

V31_BODY = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-26855",
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "CHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            },
                        }
                    ]
                },
            }
        }
    ]
}

NO_METRICS_BODY = {
    "vulnerabilities": [{"cve": {"id": "CVE-0000-00001", "metrics": {}}}]
}

NOT_FOUND_BODY = {"vulnerabilities": []}


def _cvss_entry(source, type_, base_score, base_severity="CRITICAL"):
    return {
        "source": source,
        "type": type_,
        "cvssData": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "baseScore": base_score,
            "baseSeverity": base_severity,
        },
    }


# Real shape from CVE-2020-1472 (ZeroLogon): Microsoft's own CNA score
# (5.5/medium) listed before NVD's own analysis (10.0/critical), and
# neither is tagged "Primary" -- this is the case that broke a naive
# entries[0] selection.
ZEROLOGON_MULTI_SCORER_BODY = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2020-1472",
                "metrics": {
                    "cvssMetricV31": [
                        _cvss_entry("secure@microsoft.com", "Secondary", 5.5, "MEDIUM"),
                        _cvss_entry("nvd@nist.gov", "Secondary", 10.0, "CRITICAL"),
                    ]
                },
            }
        }
    ]
}

# NVD's entry is tagged "Primary" but is not first in the array.
PRIMARY_NOT_FIRST_BODY = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-23397",
                "metrics": {
                    "cvssMetricV31": [
                        _cvss_entry("secure@microsoft.com", "Secondary", 7.5, "HIGH"),
                        _cvss_entry("nvd@nist.gov", "Primary", 9.8, "CRITICAL"),
                    ]
                },
            }
        }
    ]
}


class _FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def test_scored_cve_returns_cvss_base_score_and_vector(tmp_path: Path):
    cache = SnapshotCache(tmp_path)
    cache.write("nvd", "CVE-2021-26855", V31_BODY)

    cvss = lookup("CVE-2021-26855", cache)

    assert cvss is not None
    assert cvss.base_score == pytest.approx(9.8)
    assert cvss.base_severity == "critical"
    assert cvss.version == "3.1"
    assert cvss.vector_string == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert cvss.attack_vector == "NETWORK"
    assert cvss.privileges_required == "NONE"


def test_prefers_nvds_own_score_over_a_cna_score_when_neither_is_primary(tmp_path: Path):
    """Regression for the ZeroLogon bug: entries[0] would have returned
    Microsoft's 5.5/medium instead of NVD's own 10.0/critical."""
    cache = SnapshotCache(tmp_path)
    cache.write("nvd", "CVE-2020-1472", ZEROLOGON_MULTI_SCORER_BODY)

    cvss = lookup("CVE-2020-1472", cache)

    assert cvss.base_score == pytest.approx(10.0)
    assert cvss.base_severity == "critical"


def test_prefers_primary_entry_even_when_not_first(tmp_path: Path):
    cache = SnapshotCache(tmp_path)
    cache.write("nvd", "CVE-2023-23397", PRIMARY_NOT_FIRST_BODY)

    cvss = lookup("CVE-2023-23397", cache)

    assert cvss.base_score == pytest.approx(9.8)
    assert cvss.base_severity == "critical"


def test_cve_with_no_metrics_returns_none(tmp_path: Path):
    cache = SnapshotCache(tmp_path)
    cache.write("nvd", "CVE-0000-00001", NO_METRICS_BODY)
    assert lookup("CVE-0000-00001", cache) is None


def test_cve_not_found_returns_none(tmp_path: Path):
    cache = SnapshotCache(tmp_path)
    cache.write("nvd", "CVE-0000-00002", NOT_FOUND_BODY)
    assert lookup("CVE-0000-00002", cache) is None


def test_online_miss_fetches_via_requests_and_caches(tmp_path: Path, monkeypatch):
    calls = []

    def fake_get(url, params, headers, timeout):
        calls.append((url, params))
        return _FakeResponse(200, V31_BODY)

    monkeypatch.setattr("rhinosecure.enrich.nvd.requests.get", fake_get)

    cache = SnapshotCache(tmp_path)
    cvss = lookup("CVE-2021-26855", cache)

    assert calls == [(NVD_URL, {"cveId": "CVE-2021-26855"})]
    assert cvss.base_score == pytest.approx(9.8)

    calls.clear()
    lookup("CVE-2021-26855", cache)
    assert calls == []  # second lookup must hit the snapshot, not fetch again


def test_offline_hit_loads_from_snapshot_without_network(tmp_path: Path, monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("requests.get must not be called on an offline hit")

    monkeypatch.setattr("rhinosecure.enrich.nvd.requests.get", fail_if_called)

    cache = SnapshotCache(tmp_path, offline=True)
    cache.write("nvd", "CVE-2021-26855", V31_BODY)

    cvss = lookup("CVE-2021-26855", cache)
    assert cvss.base_score == pytest.approx(9.8)


def test_offline_miss_raises_without_network(tmp_path: Path, monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("requests.get must not be called on an offline miss")

    monkeypatch.setattr("rhinosecure.enrich.nvd.requests.get", fail_if_called)

    cache = SnapshotCache(tmp_path, offline=True)
    with pytest.raises(OfflineCacheMissError):
        lookup("CVE-2021-26855", cache)


# --- retry with backoff -----------------------------------------------------


def test_429_retries_with_backoff_then_succeeds(tmp_path: Path, monkeypatch):
    responses = [_FakeResponse(429), _FakeResponse(429), _FakeResponse(200, V31_BODY)]
    call_count = {"n": 0}

    def fake_get(url, params, headers, timeout):
        i = call_count["n"]
        call_count["n"] += 1
        return responses[i]

    sleeps = []
    monkeypatch.setattr("rhinosecure.enrich.nvd.requests.get", fake_get)
    monkeypatch.setattr("rhinosecure.enrich.nvd.time.sleep", lambda seconds: sleeps.append(seconds))

    cache = SnapshotCache(tmp_path)
    cvss = lookup("CVE-2021-26855", cache)

    assert call_count["n"] == 3
    assert cvss.base_score == pytest.approx(9.8)
    assert sleeps == [3, 6]  # RETRY_BACKOFF_BASE_SECONDS * 2**attempt, attempts 0 and 1


def test_403_also_retries(tmp_path: Path, monkeypatch):
    responses = [_FakeResponse(403), _FakeResponse(200, V31_BODY)]
    call_count = {"n": 0}

    def fake_get(url, params, headers, timeout):
        i = call_count["n"]
        call_count["n"] += 1
        return responses[i]

    monkeypatch.setattr("rhinosecure.enrich.nvd.requests.get", fake_get)
    monkeypatch.setattr("rhinosecure.enrich.nvd.time.sleep", lambda seconds: None)

    cache = SnapshotCache(tmp_path)
    cvss = lookup("CVE-2021-26855", cache)
    assert call_count["n"] == 2
    assert cvss.base_score == pytest.approx(9.8)


def test_exhausted_retries_raises(tmp_path: Path, monkeypatch):
    call_count = {"n": 0}

    def fake_get(url, params, headers, timeout):
        call_count["n"] += 1
        return _FakeResponse(429)

    sleeps = []
    monkeypatch.setattr("rhinosecure.enrich.nvd.requests.get", fake_get)
    monkeypatch.setattr("rhinosecure.enrich.nvd.time.sleep", lambda seconds: sleeps.append(seconds))

    cache = SnapshotCache(tmp_path)
    with pytest.raises(requests.HTTPError):
        lookup("CVE-2021-26855", cache)

    assert call_count["n"] == 5  # MAX_ATTEMPTS
    assert sleeps == [3, 6, 12, 24]  # one sleep between each of the 5 attempts


def test_non_retryable_error_raises_immediately(tmp_path: Path, monkeypatch):
    call_count = {"n": 0}

    def fake_get(url, params, headers, timeout):
        call_count["n"] += 1
        return _FakeResponse(500)

    monkeypatch.setattr("rhinosecure.enrich.nvd.requests.get", fake_get)
    monkeypatch.setattr(
        "rhinosecure.enrich.nvd.time.sleep",
        lambda seconds: (_ for _ in ()).throw(AssertionError("must not sleep/retry on a 500")),
    )

    cache = SnapshotCache(tmp_path)
    with pytest.raises(requests.HTTPError):
        lookup("CVE-2021-26855", cache)
    assert call_count["n"] == 1


def test_api_key_used_when_set(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "test-key-123")
    captured = {}

    def fake_get(url, params, headers, timeout):
        captured["headers"] = headers
        return _FakeResponse(200, V31_BODY)

    monkeypatch.setattr("rhinosecure.enrich.nvd.requests.get", fake_get)
    cache = SnapshotCache(tmp_path)
    lookup("CVE-2021-26855", cache)
    assert captured["headers"] == {"apiKey": "test-key-123"}


def test_no_api_key_omits_header(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    captured = {}

    def fake_get(url, params, headers, timeout):
        captured["headers"] = headers
        return _FakeResponse(200, V31_BODY)

    monkeypatch.setattr("rhinosecure.enrich.nvd.requests.get", fake_get)
    cache = SnapshotCache(tmp_path)
    lookup("CVE-2021-26855", cache)
    assert captured["headers"] == {}
