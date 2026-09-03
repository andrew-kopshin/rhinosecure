"""One-off, standalone script -- NOT part of the pytest suite and NOT wired
into the CLI -- that produces `out/export_agents_sample.json`: a small,
synthetic 3-finding fixture run through the real `Coordinator`/ToT dispatch
machinery with `crewai.Crew` mocked out (the same pattern
`tests/test_export.py`'s `test_agents_export_full_shape_with_contested_finding_and_constraint`
uses), so it costs nothing and makes no real network or LLM calls.

This is deliberately NOT the 24-finding demo fixture replayed through
--agents -- hand-fabricating 24 findings' worth of plausible per-stage
agent prose would not be real agent output, and passing it off as such
would be worse than not having a sample at all. This is a small, clearly
synthetic fixture that exists to exercise the parts of the export schema
--offline can't: RiskRecommendation's verdict_summary/narrative/
constraints_applied, a contested finding's Tree-of-Thought branches, and
an asset-scoped constraint's real before/after delta -- see CLAUDE.md
Section 8 rule 2 and "Trust boundary and provider independence" for why no
script in this repo may make a real, paid LLM call without being asked.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

ASSETS_CSV = (
    "asset_id,hostname,os,os_build,role,business_function,criticality,internet_exposed,"
    "environment,data_sensitivity,patch_window,patch_restrictions,compensating_controls,owner\n"
    "A01,EXCH01,Windows Server 2019,17763,exchange,Mail server,5,True,prod,confidential,"
    "Sun 02:00-06:00,,,messaging-team\n"
    "A02,WKS01,Windows 10,19045,workstation,Finance workstation,2,False,prod,confidential,,,,it-helpdesk\n"
    "A03,WKS02,Windows 10,19045,workstation,Engineering workstation,3,False,prod,internal,,,,it-helpdesk\n"
)

FINDINGS_CSV = (
    "finding_id,asset_id,cve_id,detected_date,scanner_severity,product,version,port,service,evidence\n"
    "F01,A01,CVE-2021-26855,2026-08-01,critical,Microsoft Exchange Server,2016 CU19,443,https,OWA SSRF chain\n"
    "F02,A02,CVE-2018-8410,2026-08-08,high,Microsoft OLE DB Driver,18.2,1433,mssql,Outdated OLE DB provider\n"
    "F03,A03,CVE-2020-1472,2026-08-09,critical,Netlogon,x,445,smb,Zerologon\n"
)


def _research_json(fid, cve_id, *, is_kev=False):
    return json.dumps({
        "finding_id": fid, "cve_id": cve_id, "scanner_severity": "high", "is_kev": is_kev,
        "exploitation_summary": "Synthetic sample data -- not a real model response.",
        "sources": ["sample-research"],
    })


def _environment_json(fid, cve_id, asset_id, hostname):
    return json.dumps({
        "finding_id": fid, "cve_id": cve_id, "asset_id": asset_id, "hostname": hostname,
        "os": "Windows", "os_build": "1", "os_build_consistent": True,
        "os_build_consistent_provenance": "model_judgment", "role": "workstation", "environment": "prod",
        "internet_exposed": False, "compensating_controls": [], "has_patch_window": False,
        "patch_window": "", "patch_restrictions": "",
        "applicability_summary": "Synthetic sample data -- not a real model response.",
        "sources": ["sample-environment"],
    })


def _tot_proposal(strategy, text):
    return json.dumps({"strategy": strategy, "proposal": text})


def _tot_critique(strategy, **scores):
    return json.dumps({"strategy": strategy, "justification": "Synthetic sample data.", **scores})


def main() -> None:
    from crewai.types.usage_metrics import UsageMetrics

    from rhinosecure.agents import coordinator as coordinator_module
    from rhinosecure.agents.coordinator import Coordinator
    from rhinosecure import tot as tot_module
    from rhinosecure.export import write_run_export
    from rhinosecure.ingest import join_findings
    from rhinosecure.memory import Memory

    class _FakeCrew:
        def __init__(self, agents, tasks, process=None, verbose=False):
            self.tasks = tasks
            self.agent = agents[0]
            self.usage_metrics = UsageMetrics(total_tokens=120 * len(tasks), successful_requests=len(tasks))

        def kickoff(self):
            is_risk_stage = any(t.name == "score_finding" for t in self.agent.tools)
            for task in self.tasks:
                if is_risk_stage:
                    finding_id = _FakeCrew.queue.pop(0)
                    tool_result = json.loads(self.agent.tools[0].run(finding_id=finding_id))
                    raw = json.dumps({
                        "finding_id": tool_result["finding_id"], "cve_id": tool_result["cve_id"],
                        "asset_id": tool_result["asset_id"], "hostname": tool_result["hostname"],
                        "risk_score": tool_result["risk_score"], "bucket": tool_result["bucket"],
                        "scoring_rationale": tool_result["rationale"],
                        "constraints_applied": tool_result["constraints_applied"],
                        "verdict_summary": "Synthetic sample verdict_summary -- not a real model response.",
                        "narrative": "Synthetic sample narrative -- not a real model response.",
                        "sources": ["sample-risk"],
                    })
                else:
                    raw = _FakeCrew.queue.pop(0)
                task.output = SimpleNamespace(raw=raw)
            return None

    _FakeCrew.queue = []

    class _FakeTotCrew:
        def __init__(self, agents, tasks, process=None, verbose=False):
            self.tasks = tasks
            self.usage_metrics = UsageMetrics(total_tokens=200 * len(tasks), successful_requests=len(tasks))

        def kickoff(self):
            for task in self.tasks:
                task.output = SimpleNamespace(raw=_FakeTotCrew.queue.pop(0))
            return None

    _FakeTotCrew.queue = []

    coordinator_module.Crew = _FakeCrew
    tot_module.Crew = _FakeTotCrew

    sample_dir = REPO_ROOT / "out" / "_agents_sample_data"
    sample_dir.mkdir(parents=True, exist_ok=True)
    (sample_dir / "assets.csv").write_text(ASSETS_CSV, encoding="utf-8")
    (sample_dir / "findings.csv").write_text(FINDINGS_CSV, encoding="utf-8")

    db_path = REPO_ROOT / "out" / "_agents_sample.db"
    db_path.unlink(missing_ok=True)
    memory = Memory(db_path)
    memory.add_constraint(
        "A02", "the finance workstation now sits behind a WAF",
        effect_kind="compensating_control", effect_value="WAF rule enabled",
    )

    findings = list(join_findings(sample_dir / "findings.csv", sample_dir / "assets.csv"))
    _FakeCrew.queue = [
        _research_json("F01", "CVE-2021-26855"),
        _research_json("F02", "CVE-2018-8410"),
        _research_json("F03", "CVE-2020-1472", is_kev=True),
        _environment_json("F01", "CVE-2021-26855", "A01", "EXCH01"),
        _environment_json("F02", "CVE-2018-8410", "A02", "WKS01"),
        _environment_json("F03", "CVE-2020-1472", "A03", "WKS02"),
        "F01", "F02", "F03",
    ]
    _FakeTotCrew.queue = [
        _tot_proposal("emergency_change", "Patch F03 tonight via an expedited change -- synthetic sample."),
        _tot_proposal("establish_window", "Schedule a Sunday window for A03 -- synthetic sample."),
        _tot_proposal("build_control", "Isolate A03 on the network until patched -- synthetic sample."),
        _tot_critique("emergency_change", risk_reduction=9, operational_cost=3,
                      constraint_compliance=8, evidence_strength=8, contradicting_evidence=1),
        _tot_critique("establish_window", risk_reduction=3, operational_cost=5,
                      constraint_compliance=4, evidence_strength=3, contradicting_evidence=6),
        _tot_critique("build_control", risk_reduction=2, operational_cost=6,
                      constraint_compliance=3, evidence_strength=2, contradicting_evidence=7),
    ]

    coordinator = Coordinator(sample_dir, memory=memory)
    coordinator.run(findings)

    export_path = REPO_ROOT / "out" / "export_agents_sample.json"
    write_run_export(
        export_path, fmt="native", data_dir=sample_dir, seed=42, offline=False,
        agents=True, coordinator=coordinator, memory=memory,
    )
    memory.close()
    print(f"wrote {export_path}")


if __name__ == "__main__":
    main()
