from pathlib import Path

import pytest

from rhinosecure.enrich import attack
from rhinosecure.enrich.attack import BUNDLE_URL, CACHE_KEY, SOURCE, load_index
from rhinosecure.enrich.cache import OfflineCacheMissError, SnapshotCache

# A small STIX-shaped fixture, not the real bundle: two techniques worth
# keeping (one Windows+Linux, one Windows-only), and three that must be
# filtered out (non-Windows, revoked, deprecated) even though the last two
# are tagged Windows. "uses" relationships give T1190 a higher use_count than
# Port Monitors (3 vs. 1) so prevalence is meaningfully distinguishable, and
# one relationship's description names a real-shaped CVE ID for the
# confirmed-match path. The excluded technique's relationship (mentioning its
# own CVE) checks that filtering happens before CVE-mention extraction too.
FAKE_BUNDLE = {
    "objects": [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--aaa1",
            "name": "Exploit Public-Facing Application",
            "description": "Adversaries may exploit weaknesses in an internet-facing web server or application to gain initial access.",
            "x_mitre_platforms": ["Windows", "Linux"],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--bbb2",
            "name": "Port Monitors",
            "description": "Adversaries may configure a malicious print spooler port monitor to gain persistence.",
            "x_mitre_platforms": ["Windows"],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "persistence"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1547.010"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--ccc3",
            "name": "macOS Only Technique",
            "description": "Some macOS-specific behavior mentioning CVE-9999-00001.",
            "x_mitre_platforms": ["macOS"],
            "kill_chain_phases": [],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9001"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--ddd4",
            "name": "Revoked Technique",
            "description": "Superseded by another technique.",
            "x_mitre_platforms": ["Windows"],
            "revoked": True,
            "kill_chain_phases": [],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9002"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--eee5",
            "name": "Deprecated Technique",
            "description": "No longer tracked.",
            "x_mitre_platforms": ["Windows"],
            "x_mitre_deprecated": True,
            "kill_chain_phases": [],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9003"}],
        },
        {
            "type": "relationship",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--group1",
            "target_ref": "attack-pattern--aaa1",
            "description": "Group1 exploited CVE-2021-26855 in Microsoft Exchange Server (ProxyLogon) for initial access.",
        },
        {
            "type": "relationship",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--group2",
            "target_ref": "attack-pattern--aaa1",
            "description": "Group2 also exploited public-facing applications.",
        },
        {
            "type": "relationship",
            "relationship_type": "uses",
            "source_ref": "malware--tool1",
            "target_ref": "attack-pattern--aaa1",
            "description": "Tool1 automates exploitation of public-facing applications.",
        },
        {
            "type": "relationship",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--group3",
            "target_ref": "attack-pattern--bbb2",
            "description": "Group3 configured a malicious print spooler port monitor for persistence.",
        },
        {
            "type": "relationship",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--group4",
            "target_ref": "attack-pattern--ccc3",
            "description": "Group4 used CVE-9999-00001 on macOS.",
        },
    ]
}


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def _filtered_payload() -> dict:
    """Run the real filter against FAKE_BUNDLE without touching the network."""
    original_get = attack.requests.get
    attack.requests.get = lambda *a, **k: _FakeResponse(FAKE_BUNDLE)
    try:
        return attack._fetch_and_filter()
    finally:
        attack.requests.get = original_get


def _index(tmp_path: Path) -> attack.TechniqueIndex:
    cache = SnapshotCache(tmp_path)
    cache.write(SOURCE, CACHE_KEY, _filtered_payload())
    return load_index(cache)


def test_filters_to_windows_not_revoked_not_deprecated(tmp_path: Path):
    index = _index(tmp_path)

    assert index.lookup("CVE-2021-26855")  # T1190 present
    # None of the excluded techniques' ids leak into the index at all.
    for excluded_id in ("T9001", "T9002", "T9003"):
        assert excluded_id not in index._techniques


def test_confirmed_match_from_cve_named_in_procedure_example(tmp_path: Path):
    index = _index(tmp_path)

    matches = index.lookup("CVE-2021-26855", product="irrelevant", evidence="irrelevant")

    assert len(matches) == 1
    assert matches[0].confidence == "confirmed"
    assert matches[0].technique.technique_id == "T1190"
    assert "CVE-2021-26855" in matches[0].reason


def test_excluded_technique_relationship_does_not_leak_a_cve_mention(tmp_path: Path):
    index = _index(tmp_path)

    # CVE-9999-00001 was only mentioned in a relationship targeting the
    # macOS-only (filtered-out) technique -- it must not resolve to anything.
    assert index.lookup("CVE-9999-00001", product="", evidence="") == []


def test_prevalence_reflects_relative_use_count(tmp_path: Path, monkeypatch):
    index = _index(tmp_path)
    # Same reasoning as test_semantic_fallback_...: this fixture's cosine
    # similarities don't reach the real-corpus-calibrated cutoff.
    monkeypatch.setattr(attack, "MIN_CANDIDATE_SIMILARITY", 0.0)

    exploit_public_facing = index.lookup("CVE-2021-26855")[0].technique  # use_count=3
    port_monitors = index.lookup(
        "CVE-0000-00000", product="Windows Print Spooler", evidence="malicious port monitor persistence"
    )[0].technique  # use_count=1

    assert port_monitors.technique_id == "T1547.010"
    assert exploit_public_facing.prevalence > port_monitors.prevalence
    assert 0.0 <= port_monitors.prevalence <= 1.0
    assert 0.0 <= exploit_public_facing.prevalence <= 1.0


def test_semantic_fallback_ranks_product_specific_technique_higher(tmp_path: Path, monkeypatch):
    index = _index(tmp_path)
    # This tiny 2-technique fixture can't reproduce the cosine-similarity
    # scale the real ~474-technique corpus calibrates MIN_CANDIDATE_SIMILARITY
    # against (see attack.py's module comment) -- lower it so this test can
    # isolate the ranking behavior itself rather than the calibrated cutoff.
    monkeypatch.setattr(attack, "MIN_CANDIDATE_SIMILARITY", 0.0)

    matches = index.lookup(
        "CVE-NOT-MENTIONED-ANYWHERE",
        product="Windows Print Spooler",
        evidence="malicious port monitor persistence technique",
    )

    assert matches
    assert matches[0].confidence == "candidate"
    assert matches[0].technique.technique_id == "T1547.010"
    assert "semantic similarity=" in matches[0].reason


def test_no_match_in_either_tier_returns_empty(tmp_path: Path, monkeypatch):
    index = _index(tmp_path)
    monkeypatch.setattr(attack, "MIN_CANDIDATE_SIMILARITY", 0.0)

    matches = index.lookup("CVE-NOT-MENTIONED-ANYWHERE", product="", evidence="")

    assert matches == []


def test_confirmed_match_ignores_product_and_evidence_text(tmp_path: Path):
    """A confirmed CVE-mention match must win outright -- it is never
    diluted or replaced by whatever vector retrieval over product/evidence
    would separately have found. See attack.py's lookup docstring."""
    index = _index(tmp_path)

    matches = index.lookup(
        "CVE-2021-26855", product="Windows Print Spooler", evidence="print spooler port monitor"
    )

    assert len(matches) == 1
    assert matches[0].confidence == "confirmed"
    assert matches[0].technique.technique_id == "T1190"


def test_online_miss_fetches_via_requests_and_caches(tmp_path: Path, monkeypatch):
    calls = []

    def fake_get(url, timeout):
        calls.append((url, timeout))
        return _FakeResponse(FAKE_BUNDLE)

    monkeypatch.setattr("rhinosecure.enrich.attack.requests.get", fake_get)

    cache = SnapshotCache(tmp_path)
    index = load_index(cache)

    assert calls == [(BUNDLE_URL, attack.REQUEST_TIMEOUT_SECONDS)]
    assert index.lookup("CVE-2021-26855")

    calls.clear()
    load_index(cache)
    assert calls == []  # second load must hit the snapshot, not fetch again


def test_offline_hit_loads_from_snapshot_without_network(tmp_path: Path, monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("requests.get must not be called on an offline hit")

    monkeypatch.setattr("rhinosecure.enrich.attack.requests.get", fail_if_called)

    cache = SnapshotCache(tmp_path, offline=True)
    cache.write(SOURCE, CACHE_KEY, _filtered_payload())

    index = load_index(cache)
    assert index.lookup("CVE-2021-26855")


def test_offline_miss_raises_without_network(tmp_path: Path, monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("requests.get must not be called on an offline miss")

    monkeypatch.setattr("rhinosecure.enrich.attack.requests.get", fail_if_called)

    cache = SnapshotCache(tmp_path, offline=True)
    with pytest.raises(OfflineCacheMissError):
        load_index(cache)
