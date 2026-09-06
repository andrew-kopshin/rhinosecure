"""Baseline coverage for `web/server.py`'s read-only routes -- there was no
test file for this module at all before the job substrate (`web/jobs.py`)
was added, so this exists first, as a regression net under the existing
behavior, before anything write-capable is wired into `create_app`.

Also carries the AST-based check mirroring `test_cli.py`'s
`test_cli_module_does_not_import_crewai_at_module_level`: `web/server.py`
must never import `rhinosecure.cli`, `rhinosecure.agents`, `rhinosecure.memory`,
or `crewai` at module level, regardless of whether jobs are enabled --
`create_app`'s conditional `from rhinosecure.web.jobs import ...` is the
only place any of that may be reached, and only when `jobs_enabled=True`.
"""

from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import rhinosecure.web.server as server_module
from rhinosecure.web.server import create_app


def test_server_module_never_imports_write_capable_modules_at_module_level():
    tree = ast.parse(Path(inspect.getfile(server_module)).read_text(encoding="utf-8"))
    top_level_imports = []
    for node in tree.body:  # module-level only, not nested in function bodies
        if isinstance(node, ast.Import):
            top_level_imports += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            top_level_imports.append(node.module)

    forbidden_prefixes = ("crewai", "rhinosecure.agents", "rhinosecure.memory", "rhinosecure.cli")
    offenders = [name for name in top_level_imports if name.startswith(forbidden_prefixes)]
    assert offenders == []


@pytest.fixture
def export_file(tmp_path: Path) -> Path:
    path = tmp_path / "export.json"
    path.write_text(json.dumps({"export_schema_version": "1.0.0", "findings": []}), encoding="utf-8")
    return path


def test_get_export_returns_the_file_contents(export_file):
    client = TestClient(create_app(export_file))
    resp = client.get("/api/export")
    assert resp.status_code == 200
    assert resp.json()["export_schema_version"] == "1.0.0"


def test_get_export_re_reads_the_file_on_every_request(export_file):
    """No in-process caching -- overwriting the file between two requests
    must be visible on the second one without restarting the app."""
    client = TestClient(create_app(export_file))
    assert client.get("/api/export").json()["findings"] == []

    export_file.write_text(
        json.dumps({"export_schema_version": "1.0.0", "findings": [{"finding_id": "F01"}]}),
        encoding="utf-8",
    )
    assert client.get("/api/export").json()["findings"] == [{"finding_id": "F01"}]


def test_get_export_missing_file_is_a_404_not_a_startup_failure(tmp_path):
    missing = tmp_path / "does_not_exist.json"
    client = TestClient(create_app(missing))  # construction must not raise
    resp = client.get("/api/export")
    assert resp.status_code == 404


def test_default_export_path_is_not_the_demo_fixtures_own_output_file():
    """The conversational front end's empty-workspace design: a fresh
    `rhino web` must open empty even on a checkout where `rhino run
    --data demo --export out/export_demo.json` was already run for
    testing -- DEFAULT_EXPORT_PATH must never be export_demo.json."""
    assert server_module.DEFAULT_EXPORT_PATH.name != "export_demo.json"
    assert server_module.DEFAULT_EXPORT_PATH.name == "export_web.json"


def test_get_export_invalid_json_is_a_500_with_a_clear_message(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("this is not json", encoding="utf-8")
    client = TestClient(create_app(bad))
    resp = client.get("/api/export")
    assert resp.status_code == 500
    assert "not valid JSON" in resp.json()["detail"]


def test_health_reports_the_resolved_path_and_existence(export_file):
    client = TestClient(create_app(export_file))
    resp = client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["export_filename"] == export_file.name
    assert body["export_exists"] is True


def test_index_serves_the_static_page(export_file):
    client = TestClient(create_app(export_file))
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_default_app_has_no_job_routes_at_all(export_file):
    """`create_app(export_file)` -- jobs_enabled omitted -- must be
    byte-for-byte today's read-only surface: a route that doesn't exist,
    not one that exists and rejects. Confirms `web/jobs.py` is never even
    imported for the default/common case."""
    client = TestClient(create_app(export_file))
    resp = client.post("/api/jobs", json={"kind": "constraint_submit", "text": "anything"})
    assert resp.status_code == 404

    resp = client.get("/api/jobs/does-not-matter")
    assert resp.status_code == 404


def test_jobs_enabled_false_explicitly_also_has_no_job_routes(export_file):
    client = TestClient(create_app(export_file, jobs_enabled=False))
    resp = client.post("/api/jobs", json={"kind": "constraint_submit", "text": "anything"})
    assert resp.status_code == 404
