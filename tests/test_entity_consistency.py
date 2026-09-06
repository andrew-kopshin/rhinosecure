from rhinosecure.agents.entity_consistency import find_wrong_cve_mentions


def test_no_mention_at_all_is_not_a_mismatch():
    assert find_wrong_cve_mentions("some plain prose with no identifiers", "CVE-2021-26855") == set()


def test_mentioning_only_the_real_cve_is_not_a_mismatch():
    text = "This CVE-2021-26855 (ProxyLogon) issue is critical and KEV-listed."
    assert find_wrong_cve_mentions(text, "CVE-2021-26855") == set()


def test_case_insensitive_on_both_sides():
    assert find_wrong_cve_mentions("see cve-2021-26855 for details", "CVE-2021-26855") == set()
    assert find_wrong_cve_mentions("see CVE-2021-26855 for details", "cve-2021-26855") == set()


def test_mentioning_a_different_cve_is_a_mismatch():
    text = "This looks similar to CVE-2020-1472 (Zerologon)."
    assert find_wrong_cve_mentions(text, "CVE-2021-26855") == {"CVE-2020-1472"}


def test_mentioning_multiple_wrong_cves_returns_all_of_them():
    text = "Related to CVE-2020-1472 and also CVE-2019-1068, unlike CVE-2021-26855 itself."
    assert find_wrong_cve_mentions(text, "CVE-2021-26855") == {"CVE-2020-1472", "CVE-2019-1068"}


def test_real_and_wrong_mentions_together_reports_only_the_wrong_one():
    text = "CVE-2021-26855 is the real issue here, not CVE-2020-1472."
    assert find_wrong_cve_mentions(text, "CVE-2021-26855") == {"CVE-2020-1472"}
