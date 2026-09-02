import json
from pathlib import Path

from crewai import Task

from rhinosecure.agents.research import (
    build_research_agent,
    build_research_task,
    build_research_tools,
)
from rhinosecure.enrich.cache import SnapshotCache
from rhinosecure.llm import LLMConfig, get_llm
from rhinosecure.schema import Asset, EnrichedFinding, Finding

# Same shapes tests/test_kev.py, test_nvd.py, test_epss.py already seed --
# reused here so the tool wrappers are checked against real response
# shapes, not an independently-invented fixture.
NVD_BODY = {
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

KEV_CATALOG = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-26855",
            "dateAdded": "2021-11-03",
            "dueDate": "2021-11-17",
        }
    ]
}

EPSS_BODY = {
    "data": [{"cve": "CVE-2021-26855", "epss": "0.97531", "percentile": "0.99912", "date": "2026-08-27"}]
}

# Pre-filtered shape TechniqueIndex expects -- same as enrich/attack.py's
# _fetch_and_filter output, hand-built instead of run through the real
# filter since the point here is exercising the tool wrapper, not
# re-testing the filter itself (test_attack.py already does that).
ATTACK_PAYLOAD = {
    "techniques": [
        {
            "technique_id": "T1190",
            "name": "Exploit Public-Facing Application",
            "description": "Adversaries may exploit weaknesses in an internet-facing application to gain initial access.",
            "tactics": ["initial-access"],
            "platforms": ["Windows"],
            "use_count": 3,
            "prevalence": 1.0,
        },
        {
            "technique_id": "T1547.010",
            "name": "Port Monitors",
            "description": "Adversaries may configure a malicious print spooler port monitor to gain persistence.",
            "tactics": ["persistence"],
            "platforms": ["Windows"],
            "use_count": 1,
            "prevalence": 0.5,
        },
    ],
    "cve_mentions": {"CVE-2021-26855": ["T1190"]},
}


def _seeded_cache(tmp_path: Path) -> SnapshotCache:
    cache = SnapshotCache(tmp_path)
    cache.write("nvd", "CVE-2021-26855", NVD_BODY)
    cache.write("kev", None, KEV_CATALOG)
    cache.write("epss", "CVE-2021-26855", EPSS_BODY)
    cache.write("attack", "enterprise-windows", ATTACK_PAYLOAD)
    return cache


def _tools(tmp_path: Path):
    cache = _seeded_cache(tmp_path)
    call_log: list[dict] = []
    tools = build_research_tools(cache, call_log)
    return {t.name: t for t in tools}, call_log


def test_returns_the_four_named_tools(tmp_path: Path):
    tools, _ = _tools(tmp_path)
    assert set(tools) == {
        "lookup_nvd",
        "lookup_kev",
        "lookup_epss",
        "lookup_attack_techniques",
    }


def test_lookup_nvd_returns_authoritative_score_and_logs_the_call(tmp_path: Path):
    tools, call_log = _tools(tmp_path)

    raw = tools["lookup_nvd"].run(cve_id="CVE-2021-26855")
    result = json.loads(raw)

    assert result["base_score"] == 9.8
    assert result["base_severity"] == "critical"
    assert result["source"] == "nvd"
    assert result["retrieved_at"] is not None

    assert len(call_log) == 1
    assert call_log[0]["tool"] == "lookup_nvd"
    assert call_log[0]["args"] == {"cve_id": "CVE-2021-26855"}
    assert call_log[0]["result"] == result


def test_lookup_nvd_unscored_cve_returns_null_fields(tmp_path: Path):
    cache = _seeded_cache(tmp_path)
    cache.write("nvd", "CVE-0000-00001", {"vulnerabilities": []})
    tools = {t.name: t for t in build_research_tools(cache, [])}

    result = json.loads(tools["lookup_nvd"].run(cve_id="CVE-0000-00001"))
    assert result["base_score"] is None
    assert result["base_severity"] is None


def test_lookup_kev_listed_cve_reports_dates_and_logs(tmp_path: Path):
    tools, call_log = _tools(tmp_path)

    result = json.loads(tools["lookup_kev"].run(cve_id="CVE-2021-26855"))

    assert result["is_listed"] is True
    assert result["date_added"] == "2021-11-03"
    assert result["source"] == "kev"
    assert call_log[0]["tool"] == "lookup_kev"


def test_lookup_kev_unlisted_cve_reports_not_listed(tmp_path: Path):
    tools, _ = _tools(tmp_path)
    result = json.loads(tools["lookup_kev"].run(cve_id="CVE-9999-99999"))
    assert result["is_listed"] is False
    assert result["date_added"] is None


def test_lookup_epss_returns_score_and_logs(tmp_path: Path):
    tools, call_log = _tools(tmp_path)

    result = json.loads(tools["lookup_epss"].run(cve_id="CVE-2021-26855"))

    assert result["score"] == 0.97531
    assert result["percentile"] == 0.99912
    assert result["source"] == "epss"
    assert call_log[0]["tool"] == "lookup_epss"


def test_lookup_attack_techniques_confirmed_match_and_logs(tmp_path: Path):
    tools, call_log = _tools(tmp_path)

    result = json.loads(
        tools["lookup_attack_techniques"].run(
            cve_id="CVE-2021-26855", product="Microsoft Exchange Server", evidence="OWA SSRF"
        )
    )

    assert result["techniques"] == [
        {
            "technique_id": "T1190",
            "name": "Exploit Public-Facing Application",
            "confidence": "confirmed",
            "reason": "CVE-2021-26855 is explicitly named in an ATT&CK procedure example for T1190",
            "prevalence": 1.0,
        }
    ]
    assert call_log[0]["tool"] == "lookup_attack_techniques"
    assert call_log[0]["args"] == {
        "cve_id": "CVE-2021-26855",
        "product": "Microsoft Exchange Server",
        "evidence": "OWA SSRF",
    }


def test_multiple_calls_all_land_in_the_shared_call_log(tmp_path: Path):
    tools, call_log = _tools(tmp_path)
    tools["lookup_nvd"].run(cve_id="CVE-2021-26855")
    tools["lookup_kev"].run(cve_id="CVE-2021-26855")
    tools["lookup_epss"].run(cve_id="CVE-2021-26855")
    tools["lookup_attack_techniques"].run(cve_id="CVE-2021-26855")
    assert [c["tool"] for c in call_log] == [
        "lookup_nvd",
        "lookup_kev",
        "lookup_epss",
        "lookup_attack_techniques",
    ]


# --- agent/task construction (no network, no LLM call) ----------------------


def _fake_llm():
    return get_llm(LLMConfig(model="claude-sonnet-5", api_key="sk-test-key"))


def test_build_research_agent_has_role_and_all_four_tools(tmp_path: Path):
    cache = _seeded_cache(tmp_path)
    tools = build_research_tools(cache, [])
    agent = build_research_agent(tools, llm=_fake_llm())

    assert agent.role == "Vulnerability Research"
    assert {t.name for t in agent.tools} == {
        "lookup_nvd",
        "lookup_kev",
        "lookup_epss",
        "lookup_attack_techniques",
    }


def test_build_research_task_embeds_finding_fields_and_targets_research_output(tmp_path: Path):
    cache = _seeded_cache(tmp_path)
    tools = build_research_tools(cache, [])
    agent = build_research_agent(tools, llm=_fake_llm())

    finding = Finding(
        finding_id="F01",
        asset_id="A02",
        cve_id="CVE-2021-26855",
        scanner_severity="critical",
        product="Microsoft Exchange Server",
        version="2016 CU19",
        evidence="OWA endpoint vulnerable to pre-auth SSRF chain (ProxyLogon)",
    )
    asset = Asset(
        asset_id="A02",
        hostname="EXCH02",
        os="Windows Server 2016",
        os_build="14393",
        role="exchange",
        criticality=5,
        internet_exposed=True,
        environment="prod",
        data_sensitivity="confidential",
    )
    enriched = EnrichedFinding(finding=finding, asset=asset)

    task = build_research_task(enriched, agent)

    assert isinstance(task, Task)
    # No output_pydantic: CrewAI's own conversion caused an unbounded retry
    # loop on a malformed response (PROGRESS.md) -- parsing is now this
    # project's own code (agents/parsing.py), not CrewAI's.
    assert task.output_pydantic is None
    assert task.agent is agent
    assert "F01" in task.description
    assert "CVE-2021-26855" in task.description
    assert "Microsoft Exchange Server" in task.description
    assert "critical" in task.description
    assert "not wrapped in any container key" in task.expected_output
