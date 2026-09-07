import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from rhinosecure.cli import main, run_with_report
from rhinosecure.memory import Memory
from rhinosecure.scoring import Bucket

DEMO_DIR = Path(__file__).resolve().parents[1] / "data" / "demo"

FINDING_KEYS = {
    "finding_id", "cve_id", "asset_id", "hostname", "bucket", "risk_score",
    "threat_score", "impact_score", "is_kev", "asset", "rationale", "verdict_summary",
    "narrative", "constraints_applied", "cited_text", "sources", "not_collected",
    "asset_not_collected", "has_tot",
}
# The deterministic path ALONE gets a structured decomposition (CLAUDE.md's
# "drop a CSV, get a plan" spec: "This must come from the deterministic
# scorer, with no LLM involved") -- agents/risk.py's own scoring_rationale
# is prose, not scoring.ScoreDecomposition, and _agents_finding_entry
# (export.py) deliberately does not carry one.
DET_FINDING_KEYS = FINDING_KEYS | {"decomposition"}
DECOMPOSITION_THREAT_KEYS = {
    "severity_base", "severity_source", "internet_exposed", "internet_exposed_neutralized",
    "epss", "is_kev", "likelihood_multiplier", "attack_prevalence",
}
DECOMPOSITION_IMPACT_KEYS = {
    "criticality", "criticality_neutralized", "environment", "environment_neutralized",
    "data_sensitivity", "data_sensitivity_neutralized", "role", "role_neutralized",
    "composite", "compensating_controls",
}
ASSET_SUMMARY_KEYS = {"role", "internet_exposed", "criticality", "environment", "data_sensitivity"}
SOURCE_KEYS = {"source", "key", "retrieved_at"}
PIPELINE_STAGES = ("ingest", "enrichment", "scoring", "agents", "tot")


@pytest.fixture(autouse=True)
def _isolated_memory_db(tmp_path, monkeypatch):
    """Same isolation test_cli.py's own fixture applies -- keeps every test
    in this file off the real repo-root rhinosecure.db."""
    monkeypatch.setattr("rhinosecure.memory.DEFAULT_DB_PATH", tmp_path / "test-rhinosecure.db")


# --- deterministic path: schema shape -----------------------------------


def test_deterministic_export_matches_schema_shape(tmp_path):
    from rhinosecure.export import write_run_export

    result = run_with_report(DEMO_DIR, seed=42, offline=True)
    export_path = tmp_path / "export.json"

    write_run_export(
        export_path, fmt="native", data_dir=DEMO_DIR, seed=42, offline=True,
        agents=False, result=result, memory=None,
    )

    data = json.loads(export_path.read_text(encoding="utf-8"))

    assert data["export_schema_version"] == "1.2.0"
    assert data["generated_at"]  # non-empty ISO 8601 string
    assert data["run"] == {
        "data_dir": str(DEMO_DIR), "format": "native", "seed": 42, "offline": True, "agents": False,
    }
    assert data["provenance"] is None  # native is a built-in adapter -- no contract behind it
    assert data["provisional"] is False  # a plain native run is never provisional

    assert set(data["pipeline"].keys()) == set(PIPELINE_STAGES)
    for stage in ("ingest", "enrichment", "scoring"):
        assert data["pipeline"][stage]["status"] == "completed"
    assert data["pipeline"]["agents"] == {
        "status": "not_run", "detail": "run without --agents; deterministic pipeline only",
    }
    assert data["pipeline"]["tot"] == {"status": "not_run", "detail": "agents not dispatched"}
    assert "24 finding(s)" in data["pipeline"]["ingest"]["detail"]
    assert "0 duplicate row(s) collapsed" in data["pipeline"]["ingest"]["detail"]

    summary = data["summary"]
    assert summary["total_findings"] == 24
    assert set(summary["bucket_distribution"].keys()) == {b.value for b in Bucket}
    assert sum(summary["bucket_distribution"].values()) == 24
    assert summary["contested_rate"] == {"contested": 3, "total": 24, "pct": pytest.approx(12.5)}
    assert summary["data_gaps"] == {
        "format": "native", "assets_total": 12, "findings_total": 24,
        "duplicate_assets_collapsed": 0, "duplicate_findings_collapsed": 0,
        "asset_gaps": {}, "finding_gaps": {},
        "excluded_assets": {}, "excluded_findings": {},
    }

    assert len(data["findings"]) == 24
    for entry in data["findings"]:
        assert set(entry.keys()) == DET_FINDING_KEYS
        assert entry["threat_score"] is not None
        assert entry["impact_score"] is not None
        assert isinstance(entry["is_kev"], bool)
        assert set(entry["asset"].keys()) == ASSET_SUMMARY_KEYS
        assert entry["verdict_summary"] is None
        assert entry["narrative"] is None
        assert entry["constraints_applied"] == []
        assert entry["cited_text"] == []
        assert entry["has_tot"] is False  # deterministic path never dispatches ToT
        decomposition = entry["decomposition"]
        assert set(decomposition["threat"].keys()) == DECOMPOSITION_THREAT_KEYS
        assert set(decomposition["impact"].keys()) == DECOMPOSITION_IMPACT_KEYS
        # The demo fixture is a fully-mapped native run -- nothing is ever
        # neutralized there (that's the provisional-run path's own job).
        assert decomposition["impact"]["criticality_neutralized"] is False
        assert decomposition["impact"]["role_neutralized"] is False
        assert decomposition["threat"]["internet_exposed_neutralized"] is False

    by_id = {e["finding_id"]: e for e in data["findings"]}
    f14 = by_id["F14"]  # the fixture's designated contested/bad-data case
    assert f14["bucket"] == "contested"
    assert f14["cve_id"] == "CVE-2023-23397"
    assert f14["is_kev"] is True  # CVE-2023-23397 is CISA KEV-listed
    assert f14["asset"] == {
        "role": "workstation", "internet_exposed": False, "criticality": 2,
        "environment": "prod", "data_sensitivity": "confidential",
    }  # A09 / WKS-FIN12, data/demo/assets.csv
    assert any("bucket=contested" in line for line in f14["rationale"])
    source_names = {s["source"] for s in f14["sources"]}
    assert source_names == {"nvd", "kev", "epss", "attack"}
    for s in f14["sources"]:
        assert set(s.keys()) == SOURCE_KEYS
        assert s["retrieved_at"]
    kev_source = next(s for s in f14["sources"] if s["source"] == "kev")
    assert kev_source["key"] is None
    nvd_source = next(s for s in f14["sources"] if s["source"] == "nvd")
    assert nvd_source["key"] == "CVE-2023-23397"

    assert data["contested"] == []
    assert data["constraints"] == {"asset_scoped": [], "capacity": []}
    assert data["usage"] == {"research": None, "environment": None, "risk": None, "tot": None}


def test_deterministic_export_is_valid_json_written_atomically(tmp_path):
    from rhinosecure.export import write_run_export

    result = run_with_report(DEMO_DIR, seed=42, offline=True)
    export_path = tmp_path / "nested" / "dir" / "export.json"

    write_run_export(
        export_path, fmt="native", data_dir=DEMO_DIR, seed=42, offline=True,
        agents=False, result=result, memory=None,
    )

    assert export_path.exists()
    assert not export_path.with_name(export_path.name + ".tmp").exists()
    json.loads(export_path.read_text(encoding="utf-8"))  # must not raise


# --- provenance: config-driven contract identity ------------------------

BLUEPEAK_DIR = Path(__file__).resolve().parents[1] / "data" / "bluepeak"


def test_deterministic_export_carries_contract_provenance_for_a_config_driven_run(tmp_path):
    from rhinosecure.export import write_run_export

    result = run_with_report(BLUEPEAK_DIR, seed=42, adapter_config="bluepeak-gen")
    export_path = tmp_path / "export.json"

    write_run_export(
        export_path, fmt=result.report.format, data_dir=BLUEPEAK_DIR, seed=42, offline=False,
        agents=False, result=result, memory=None,
    )
    data = json.loads(export_path.read_text(encoding="utf-8"))

    contract = result.contract
    assert contract is not None  # sanity: this run actually went through ConfiguredAdapter
    assert data["provenance"] == {
        "format": contract.format,
        "version": contract.version,
        "confirmed_at": contract.review.confirmed_at,
        "confirmed_by": contract.review.confirmed_by,
        "content_digest": contract.review.content_digest,
        "decision_digest": contract.review.decision_digest,
        "scale_drift": None,  # bluepeak-gen.json's observed is null -- nothing to compare against
    }
    # the wording fix that came with provenance: the flag named is the one
    # actually used to invoke this run, never a --format that doesn't exist
    assert "via --adapter-config bluepeak-gen" in data["pipeline"]["ingest"]["detail"]


def test_deterministic_export_reports_scale_drift_when_observed_disagrees(tmp_path):
    from dataclasses import replace

    from rhinosecure.export import write_run_export

    result = run_with_report(BLUEPEAK_DIR, seed=42, adapter_config="bluepeak-gen")
    signed_contract = result.contract.model_copy(
        update={"observed": {"assets_loaded": 3, "findings_loaded": 3}}
    )
    result = replace(result, contract=signed_contract)
    export_path = tmp_path / "export.json"

    write_run_export(
        export_path, fmt=result.report.format, data_dir=BLUEPEAK_DIR, seed=42, offline=False,
        agents=False, result=result, memory=None,
    )
    data = json.loads(export_path.read_text(encoding="utf-8"))

    assert data["provenance"]["scale_drift"] == {
        "signed_assets": 3,
        "signed_findings": 3,
        "loaded_assets": result.report.assets_total,
        "loaded_findings": result.report.findings_total,
    }


def test_agents_export_carries_contract_provenance_for_a_config_driven_run(tmp_path):
    """A minimal, hand-built Coordinator stand-in -- proves the agents
    builder wires `coordinator.contract` into `provenance` the same way
    the deterministic builder wires `result.contract`, without paying for
    a real (fake-crewai) agent run just to exercise this one field."""
    from rhinosecure.adapters import load_config_adapter
    from rhinosecure.enrich.cache import SnapshotCache
    from rhinosecure.export import write_run_export

    contract = load_config_adapter("bluepeak-gen").contract
    coordinator = SimpleNamespace(
        contract=contract,
        cache=SnapshotCache(),
        _asset_index={},
        state=SimpleNamespace(
            enriched_by_id={}, research_by_id={}, research_failures={},
            environment_failures={}, risk_failures={}, tot_failures={},
            risk_by_id={}, tot_by_id={},
            research_usage=None, environment_usage=None, risk_usage=None, tot_usage=None,
        ),
        ranked=lambda: [],
    )
    export_path = tmp_path / "export.json"

    write_run_export(
        export_path, fmt="bluepeak-gen", data_dir=BLUEPEAK_DIR, seed=42, offline=False,
        agents=True, coordinator=coordinator, memory=None,
    )
    data = json.loads(export_path.read_text(encoding="utf-8"))

    assert data["provenance"]["format"] == "bluepeak-gen"
    assert data["provenance"]["version"] == contract.version
    assert data["provenance"]["confirmed_by"] == contract.review.confirmed_by


# --- deterministic path: constraints.asset_scoped's "not applied" note --


def test_deterministic_export_constraints_section_notes_it_is_not_applied(tmp_path):
    from rhinosecure.export import write_run_export

    memory = Memory(tmp_path / "mem.db")
    memory.add_constraint(
        "A02", "the exchange server now sits behind a WAF",
        effect_kind="compensating_control", effect_value="WAF rule enabled",
    )
    result = run_with_report(DEMO_DIR, seed=42, offline=True)
    export_path = tmp_path / "export.json"

    write_run_export(
        export_path, fmt="native", data_dir=DEMO_DIR, seed=42, offline=True,
        agents=False, result=result, memory=memory,
    )
    data = json.loads(export_path.read_text(encoding="utf-8"))

    [constraint] = data["constraints"]["asset_scoped"]
    assert constraint["asset_id"] == "A02"
    assert constraint["applies_to_current_run"] is True  # A02 has findings in the demo fixture
    assert constraint["deltas"] == []
    assert "not applied on the deterministic path" in constraint["note"]
    assert data["constraints"]["capacity"] == []


def test_deterministic_export_flags_a_constraint_on_an_asset_with_no_findings_in_this_run(tmp_path):
    from rhinosecure.export import write_run_export

    memory = Memory(tmp_path / "mem.db")
    memory.add_constraint(
        "NO-SUCH-ASSET", "an asset outside this dataset",
        effect_kind="patch_window", effect_value="Sun 02:00-06:00",
    )
    result = run_with_report(DEMO_DIR, seed=42, offline=True)
    export_path = tmp_path / "export.json"

    write_run_export(
        export_path, fmt="native", data_dir=DEMO_DIR, seed=42, offline=True,
        agents=False, result=result, memory=memory,
    )
    data = json.loads(export_path.read_text(encoding="utf-8"))

    [constraint] = data["constraints"]["asset_scoped"]
    assert constraint["applies_to_current_run"] is False
    # Even off the deterministic path, an asset genuinely absent from the
    # current dataset gets the "not applied" note (agents=False takes
    # priority) -- both notes are honest, "not applied" happens to be
    # checked first in _asset_scoped_constraints.
    assert constraint["note"] is not None


# --- deterministic path: capacity history is agents-independent ---------


def test_capacity_history_is_read_regardless_of_which_path_produced_the_export(tmp_path):
    from rhinosecure.export import write_run_export

    memory = Memory(tmp_path / "mem.db")
    run_id = memory.record_run(
        data_dir=str(DEMO_DIR), ingest_format="native", seed=42, offline=True, agents=False,
        total_findings=4, contested_count=0, contested_total=4,
    )
    memory.record_capacity_constraint(run_id, "only two patches fit this window", 2, 4, 2)
    memory.record_decision(
        run_id=run_id, finding_id="F01", cve_id="CVE-0000-0001", asset_id="A01", hostname="H1",
        risk_score=40.0, bucket="next_window", rationale=["r"], verdict_summary="v", narrative="n",
        capacity_rank=1, capacity_pool_size=4, capacity_limit=2,
    )
    memory.record_decision(
        run_id=run_id, finding_id="F02", cve_id="CVE-0000-0002", asset_id="A02", hostname="H2",
        risk_score=20.0, bucket="deferred_capacity", rationale=["r"], verdict_summary="v", narrative="n",
        capacity_rank=3, capacity_pool_size=4, capacity_limit=2,
    )

    result = run_with_report(DEMO_DIR, seed=42, offline=True)
    export_path = tmp_path / "export.json"
    write_run_export(
        export_path, fmt="native", data_dir=DEMO_DIR, seed=42, offline=True,
        agents=False, result=result, memory=memory,
    )
    data = json.loads(export_path.read_text(encoding="utf-8"))

    [cap] = data["constraints"]["capacity"]
    assert cap["raw_text"] == "only two patches fit this window"
    assert cap["patch_limit"] == 2
    assert cap["pool_size"] == 4
    assert cap["deferred_count"] == 2
    assert cap["stale"] is False  # same data_dir/format as the current export
    assert cap["source_run"]["data_dir"] == str(DEMO_DIR)
    assert [d["finding_id"] for d in cap["deltas"]] == ["F01", "F02"]  # rank order
    f02 = cap["deltas"][1]
    assert f02["original_bucket"] == "next_window"
    assert f02["effective_bucket"] == "deferred_capacity"
    assert f02["fits"] is False


def test_capacity_history_flags_stale_when_data_dir_differs(tmp_path):
    from rhinosecure.export import write_run_export

    memory = Memory(tmp_path / "mem.db")
    run_id = memory.record_run(
        data_dir="C:\\some\\other\\dataset", ingest_format="native", seed=1, offline=False, agents=False,
        total_findings=1, contested_count=0, contested_total=1,
    )
    memory.record_capacity_constraint(run_id, "five patches fit this window", 5, 1, 0)
    memory.record_decision(
        run_id=run_id, finding_id="F01", cve_id="CVE-0000-0001", asset_id="A01", hostname="H1",
        risk_score=10.0, bucket="next_window", rationale=["r"], verdict_summary="v", narrative="n",
        capacity_rank=1, capacity_pool_size=1, capacity_limit=5,
    )

    result = run_with_report(DEMO_DIR, seed=42, offline=True)
    export_path = tmp_path / "export.json"
    write_run_export(
        export_path, fmt="native", data_dir=DEMO_DIR, seed=42, offline=True,
        agents=False, result=result, memory=memory,
    )
    data = json.loads(export_path.read_text(encoding="utf-8"))

    [cap] = data["constraints"]["capacity"]
    assert cap["stale"] is True


# --- write_run_export misuse -------------------------------------------


def test_write_run_export_requires_result_for_the_deterministic_path(tmp_path):
    from rhinosecure.export import write_run_export

    with pytest.raises(ValueError, match="requires coordinator="):
        write_run_export(
            tmp_path / "x.json", fmt="native", data_dir=DEMO_DIR, seed=42, offline=True, agents=True,
        )


def test_write_run_export_requires_coordinator_for_the_agents_path(tmp_path):
    from rhinosecure.export import write_run_export

    result = run_with_report(DEMO_DIR, seed=42, offline=True)
    with pytest.raises(ValueError, match="requires coordinator="):
        write_run_export(
            tmp_path / "x.json", fmt="native", data_dir=DEMO_DIR, seed=42, offline=True,
            agents=True, result=result,
        )


# --- CLI wiring: strictly additive --------------------------------------


def test_export_flag_does_not_change_deterministic_console_output(tmp_path, capsys):
    export_path = tmp_path / "export.json"

    assert main(["run", "--data", "demo", "--seed", "42", "--offline"]) == 0
    without_export = capsys.readouterr().out

    assert main(["run", "--data", "demo", "--seed", "42", "--offline", "--export", str(export_path)]) == 0
    with_export = capsys.readouterr().out

    assert with_export == without_export
    assert export_path.exists()


def test_export_flag_does_not_change_agents_console_output(monkeypatch, tmp_path, capsys):
    from rhinosecure.agents.research import ResearchFinding
    from rhinosecure.agents.risk import RiskRecommendation
    from rhinosecure.enrich.cache import SnapshotCache
    from rhinosecure.ingest import join_findings

    findings = list(join_findings(DEMO_DIR / "findings.csv", DEMO_DIR / "assets.csv"))
    enriched_by_id = {e.finding.finding_id: e for e in findings}
    recommendation = RiskRecommendation(
        finding_id="F01", cve_id="CVE-2021-26855", asset_id="A02", hostname="EXCH01",
        risk_score=42.0, bucket="next_window", scoring_rationale=["fake rationale line"],
        verdict_summary="fake verdict summary.", narrative="fake narrative", sources=["fake"],
    )
    research = ResearchFinding(
        finding_id="F01", cve_id="CVE-2021-26855", scanner_severity="high",
        exploitation_summary="fake", sources=["fake-research"],
    )

    class _FakeCoordinator:
        def __init__(
            self,
            data_dir,
            cache=None,
            *,
            memory=None,
            verbose=False,
            assets=None,
            ingest_format="native",
            contract=None,
        ):
            self.memory = memory
            self.cache = cache or SnapshotCache()
            self._asset_index = assets or {}
            self.contract = contract
            self.ingest_format = ingest_format
            self.state = SimpleNamespace(
                enriched_by_id=enriched_by_id,
                research_by_id={"F01": research},
                research_failures={}, environment_failures={}, risk_failures={}, tot_failures={},
                risk_by_id={"F01": recommendation}, tot_by_id={},
                research_usage=None, environment_usage=None, risk_usage=None, tot_usage=None,
            )

        def run(self, findings):
            return self.ranked()

        def ranked(self):
            return [recommendation]

    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)
    export_path = tmp_path / "export.json"

    assert main(["run", "--data", "demo", "--agents"]) == 0
    without_export = capsys.readouterr().out

    assert main(["run", "--data", "demo", "--agents", "--export", str(export_path)]) == 0
    with_export = capsys.readouterr().out

    assert with_export == without_export
    assert export_path.exists()
    data = json.loads(export_path.read_text(encoding="utf-8"))
    assert data["run"]["agents"] is True
    assert data["findings"][0]["finding_id"] == "F01"
    assert data["findings"][0]["verdict_summary"] == "fake verdict summary."


def test_export_flag_absent_writes_no_file(tmp_path):
    export_path = tmp_path / "export.json"
    assert main(["run", "--data", "demo", "--seed", "42", "--offline"]) == 0
    assert not export_path.exists()


def test_export_error_is_reported_after_console_output_and_exits_1(tmp_path, capsys):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    bad_path = blocker / "sub" / "export.json"  # blocker is a file, not a dir -- mkdir(parents=True) must fail

    exit_code = main(["run", "--data", "demo", "--seed", "42", "--offline", "--export", str(bad_path)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "export error" in captured.err
    assert "finding_id" in captured.out  # the run's own table already printed


# --- agents path: full integration (contested finding + ToT + a constraint) --


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


@pytest.fixture
def agents_data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "agents_data"
    d.mkdir()
    (d / "assets.csv").write_text(ASSETS_CSV, encoding="utf-8")
    (d / "findings.csv").write_text(FINDINGS_CSV, encoding="utf-8")
    return d


def _research_json(fid: str, cve_id: str, *, is_kev: bool = False) -> str:
    return json.dumps({
        "finding_id": fid, "cve_id": cve_id, "scanner_severity": "high", "is_kev": is_kev,
        "exploitation_summary": "fake research summary", "sources": ["research-source"],
    })


def _environment_json(fid: str, cve_id: str, asset_id: str, hostname: str) -> str:
    return json.dumps({
        "finding_id": fid, "cve_id": cve_id, "asset_id": asset_id, "hostname": hostname,
        "os": "Windows", "os_build": "1", "os_build_consistent": True,
        "os_build_consistent_provenance": "model_judgment", "role": "workstation", "environment": "prod",
        "internet_exposed": False, "compensating_controls": [], "has_patch_window": False,
        "patch_window": "", "patch_restrictions": "", "applicability_summary": "fake environment summary",
        "sources": ["fake"],
    })


class _QueuedFakeCrew:
    """Same shape as test_coordinator.py's own fake -- Research/Environment
    stages pop raw JSON text; the Risk stage calls the real score_finding
    tool (pure deterministic Python) so a real, memory-aware call_log entry
    exists for verify_scoring_matches_tool and for this file's own delta
    assertions."""

    queue: list = []

    def __init__(self, agents, tasks, process=None, verbose=False):
        from crewai.types.usage_metrics import UsageMetrics

        self.tasks = tasks
        self.agent = agents[0]
        self.usage_metrics = UsageMetrics(total_tokens=10 * len(tasks), successful_requests=len(tasks))

    def kickoff(self):
        is_risk_stage = any(t.name == "score_finding" for t in self.agent.tools)
        for task in self.tasks:
            if is_risk_stage:
                finding_id = _QueuedFakeCrew.queue.pop(0)
                tool_result = json.loads(self.agent.tools[0].run(finding_id=finding_id))
                raw = json.dumps({
                    "finding_id": tool_result["finding_id"], "cve_id": tool_result["cve_id"],
                    "asset_id": tool_result["asset_id"], "hostname": tool_result["hostname"],
                    "risk_score": tool_result["risk_score"], "bucket": tool_result["bucket"],
                    "scoring_rationale": tool_result["rationale"],
                    "constraints_applied": tool_result["constraints_applied"],
                    "verdict_summary": "fake verdict summary.", "narrative": "fake narrative",
                    "sources": ["risk-source"],
                })
            else:
                raw = _QueuedFakeCrew.queue.pop(0)
            task.output = SimpleNamespace(raw=raw)
        return None


class _QueuedFakeTotCrew:
    """`kickoff()` increments the real agent's `agent.llm`'s own cumulative
    usage counter (`_track_token_usage_internal`), one call per task --
    production code (`tot._UsageTracker`) reads per-call usage via
    `agent.llm.get_token_usage_summary().delta_since(baseline)`, never
    `crew.usage_metrics` directly, since `_dispatch_tot` reuses one
    strategist/critic pair across every contested finding in a batch."""

    queue: list = []

    def __init__(self, agents, tasks, process=None, verbose=False):
        self.agents = agents
        self.tasks = tasks
        from crewai.types.usage_metrics import UsageMetrics
        self.usage_metrics = UsageMetrics(total_tokens=100 * len(tasks), successful_requests=len(tasks))

    def kickoff(self):
        for agent in self.agents:
            for _ in self.tasks:
                agent.llm._track_token_usage_internal({"total_tokens": 100, "prompt_tokens": 80, "completion_tokens": 20})
        for task in self.tasks:
            task.output = SimpleNamespace(raw=_QueuedFakeTotCrew.queue.pop(0))
        return None


def _tot_proposal(strategy: str, text: str) -> str:
    return json.dumps({"strategy": strategy, "proposal": text})


def _tot_critique(strategy: str, **scores) -> str:
    return json.dumps({"strategy": strategy, "justification": "fake", **scores})


def _tot_clear_winner_queue() -> list:
    return [
        _tot_proposal("emergency_change", "Patch now."),
        _tot_proposal("establish_window", "Schedule a window."),
        _tot_proposal("build_control", "Add a control."),
        _tot_critique("emergency_change", risk_reduction=9, operational_cost=3,
                      constraint_compliance=8, evidence_strength=8, contradicting_evidence=1),
        _tot_critique("establish_window", risk_reduction=3, operational_cost=5,
                      constraint_compliance=4, evidence_strength=3, contradicting_evidence=6),
        _tot_critique("build_control", risk_reduction=2, operational_cost=6,
                      constraint_compliance=3, evidence_strength=2, contradicting_evidence=7),
    ]


def test_agents_export_full_shape_with_contested_finding_and_constraint(monkeypatch, agents_data_dir, tmp_path):
    """F01 is ordinary (next_window, patch_window declared). F02's asset
    (A02) carries an active compensating_control constraint added BEFORE
    the run, so Risk's real score_finding tool folds it in -- a genuine,
    non-fabricated delta. F03's asset (A03) has neither a control nor a
    patch window and is_kev=True, so it lands contested and is routed
    through the (faked) ToT search."""
    from rhinosecure.agents import coordinator as coordinator_module
    from rhinosecure.agents.coordinator import Coordinator
    from rhinosecure.ingest import join_findings
    from rhinosecure import tot as tot_module
    from rhinosecure.export import write_run_export

    monkeypatch.setattr(coordinator_module, "Crew", _QueuedFakeCrew)
    monkeypatch.setattr(tot_module, "Crew", _QueuedFakeTotCrew)

    memory = Memory(tmp_path / "mem.db")
    memory.add_constraint(
        "A02", "the finance workstation now sits behind a WAF",
        effect_kind="compensating_control", effect_value="WAF rule enabled",
    )

    findings = list(join_findings(agents_data_dir / "findings.csv", agents_data_dir / "assets.csv"))

    _QueuedFakeCrew.queue = [
        _research_json("F01", "CVE-2021-26855"),
        _research_json("F02", "CVE-2018-8410"),
        _research_json("F03", "CVE-2020-1472", is_kev=True),
        _environment_json("F01", "CVE-2021-26855", "A01", "EXCH01"),
        _environment_json("F02", "CVE-2018-8410", "A02", "WKS01"),
        _environment_json("F03", "CVE-2020-1472", "A03", "WKS02"),
        "F01", "F02", "F03",
    ]
    _QueuedFakeTotCrew.queue = _tot_clear_winner_queue()

    coordinator = Coordinator(agents_data_dir, memory=memory)
    coordinator.run(findings)
    assert coordinator.state.risk_by_id["F03"].bucket == "contested"  # sanity: the gate actually fired

    export_path = tmp_path / "export.json"
    write_run_export(
        export_path, fmt="native", data_dir=agents_data_dir, seed=42, offline=False,
        agents=True, coordinator=coordinator, memory=memory,
    )
    data = json.loads(export_path.read_text(encoding="utf-8"))

    assert data["run"]["agents"] is True
    assert data["provenance"] is None  # this Coordinator was built with no contract (native)
    assert data["provisional"] is False  # run_agents never runs against an unconfirmed contract
    assert data["pipeline"]["agents"]["status"] == "completed"
    assert data["pipeline"]["tot"]["status"] == "completed"
    assert "1 contested finding(s) resolved, 0 failed" in data["pipeline"]["tot"]["detail"]
    assert data["pipeline"]["enrichment"]["detail"].startswith("3/3 finding(s) enriched")
    assert data["pipeline"]["scoring"]["detail"].startswith("3/3 finding(s) scored")

    assert data["summary"]["total_findings"] == 3
    assert data["summary"]["contested_rate"] == {"contested": 1, "total": 3, "pct": pytest.approx(100 / 3)}

    by_id = {f["finding_id"]: f for f in data["findings"]}
    assert set(by_id) == {"F01", "F02", "F03"}
    for entry in by_id.values():
        assert set(entry.keys()) == FINDING_KEYS
        assert entry["threat_score"] is None  # RiskRecommendation carries no such field
        assert entry["impact_score"] is None
        assert set(entry["asset"].keys()) == ASSET_SUMMARY_KEYS

    f01 = by_id["F01"]
    assert f01["is_kev"] is False  # _research_json's default
    assert f01["asset"] == {
        "role": "exchange", "internet_exposed": True, "criticality": 5,
        "environment": "prod", "data_sensitivity": "confidential",
    }  # A01 / EXCH01, this file's own ASSETS_CSV

    f02 = by_id["F02"]
    assert f02["constraints_applied"] == ["the finance workstation now sits behind a WAF"]
    assert f02["verdict_summary"] == "fake verdict summary."
    assert set(f02["cited_text"]) >= {"research-source", "risk-source"}  # Research + Risk sources, deduped
    assert f02["has_tot"] is False
    assert f02["is_kev"] is False
    assert f02["asset"] == {
        "role": "workstation", "internet_exposed": False, "criticality": 2,
        "environment": "prod", "data_sensitivity": "confidential",
    }  # A02 / WKS01 -- ground truth, unaffected by the compensating_control constraint on file

    f03 = by_id["F03"]
    assert f03["bucket"] == "contested"
    assert f03["has_tot"] is True
    assert f03["is_kev"] is True  # _research_json("F03", ..., is_kev=True) -- also why it's contested
    assert f03["asset"] == {
        "role": "workstation", "internet_exposed": False, "criticality": 3,
        "environment": "prod", "data_sensitivity": "internal",
    }  # A03 / WKS02

    [contested_entry] = data["contested"]
    assert contested_entry["finding_id"] == "F03"
    assert contested_entry["status"] == "resolved"
    assert contested_entry["failure_reason"] is None
    assert contested_entry["winner_strategy"] == "emergency_change"
    assert contested_entry["near_tie"] is False
    assert len(contested_entry["branches"]) == 2  # BEAM_WIDTH, not all 3 initial strategies
    winners = [b for b in contested_entry["branches"] if b["is_winner"]]
    assert len(winners) == 1
    assert winners[0]["strategy"] == "emergency_change"
    for branch in contested_entry["branches"]:
        assert set(branch["critic_scores"].keys()) == {
            "risk_reduction", "operational_cost", "constraint_compliance",
            "evidence_strength", "contradicting_evidence", "justification",
        }
    assert contested_entry["usage"]["successful_requests"] == 6

    assert data["usage"]["research"] is not None
    assert data["usage"]["risk"] is not None
    assert data["usage"]["tot"] is not None
    assert data["usage"]["tot"]["successful_requests"] == 6

    [constraint] = data["constraints"]["asset_scoped"]
    assert constraint["asset_id"] == "A02"
    assert constraint["applies_to_current_run"] is True
    assert constraint["note"] is None
    [delta] = constraint["deltas"]
    assert delta["finding_id"] == "F02"
    assert delta["after_risk_score"] < delta["before_risk_score"]  # the control lowers impact
    assert delta["changed"] is True
    assert "WAF rule enabled" in delta["rationale_added"][0]


def test_agents_export_records_a_tot_failure_without_usage(monkeypatch, agents_data_dir, tmp_path):
    from rhinosecure.agents import coordinator as coordinator_module
    from rhinosecure.agents.coordinator import Coordinator
    from rhinosecure.ingest import join_findings
    from rhinosecure import tot as tot_module
    from rhinosecure.export import write_run_export

    monkeypatch.setattr(coordinator_module, "Crew", _QueuedFakeCrew)
    monkeypatch.setattr(tot_module, "Crew", _QueuedFakeTotCrew)

    memory = Memory(tmp_path / "mem.db")
    findings = [
        e for e in join_findings(agents_data_dir / "findings.csv", agents_data_dir / "assets.csv")
        if e.finding.finding_id == "F03"
    ]

    _QueuedFakeCrew.queue = [
        _research_json("F03", "CVE-2020-1472", is_kev=True),
        _environment_json("F03", "CVE-2020-1472", "A03", "WKS02"),
        "F03",
    ]
    _QueuedFakeTotCrew.queue = ["not valid json", "not valid json", "not valid json"]

    coordinator = Coordinator(agents_data_dir, memory=memory, max_parse_attempts=1)
    coordinator.run(findings)
    assert "F03" in coordinator.state.tot_failures

    export_path = tmp_path / "export.json"
    write_run_export(
        export_path, fmt="native", data_dir=agents_data_dir, seed=42, offline=False,
        agents=True, coordinator=coordinator, memory=memory,
    )
    data = json.loads(export_path.read_text(encoding="utf-8"))

    [entry] = data["contested"]
    assert entry["finding_id"] == "F03"
    assert entry["status"] == "failed"
    assert entry["failure_reason"]
    assert entry["branches"] == []
    assert entry["usage"] is None  # known limitation -- see export.py's module docstring
    assert data["usage"]["tot"]["successful_requests"] == 3  # fleet-wide total still captured
