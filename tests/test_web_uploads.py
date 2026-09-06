"""Coverage for the upload mechanics (`web/uploads.py`), mounted via
`create_app(jobs_enabled=True, ...)` alongside `web/jobs.py`.

An autouse fixture monkeypatches `uploads_module.DEFAULT_UPLOADS_DIR` to a
`tmp_path` location for the whole file -- `mount_upload_routes(app)` (no
explicit `uploads_dir=`) reads that module global at call time, so this is
what keeps every test from writing into the real repo's `data/uploads/`,
the exact test-isolation bug PROGRESS.md 2026-09-03 documents for
`memory.DEFAULT_DB_PATH` under the same "an autouse-patched module global
defaults a real path" shape.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from rhinosecure.web import uploads as uploads_module
from rhinosecure.web.jobs import JobConfig
from rhinosecure.web.server import create_app


@pytest.fixture(autouse=True)
def isolated_uploads_dir(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(uploads_module, "DEFAULT_UPLOADS_DIR", tmp_path / "uploads")


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config = JobConfig(data_dir=data_dir, db_path=tmp_path / "mem.db")
    app = create_app(tmp_path / "export.json", jobs_enabled=True, job_config=config)
    return TestClient(app)


def _upload(client: TestClient, filename: str, content: bytes, **extra):
    data = {k: v for k, v in extra.items() if k not in ("headers",)}
    return client.post(
        "/api/uploads",
        files={"file": (filename, content, "text/csv")},
        data=data,
        headers=extra.get("headers"),
    )


# ---------------- default app: routes don't exist at all ----------------


def test_upload_routes_are_not_mounted_on_a_default_app(tmp_path):
    app = create_app(tmp_path / "export.json")
    client = TestClient(app)
    assert client.post("/api/uploads", files={"file": ("a.csv", b"x", "text/csv")}).status_code == 404
    assert client.get("/api/uploads/whatever").status_code == 404


# ---------------- single-file uploads ----------------


def test_single_file_upload_creates_a_ready_set(client: TestClient, tmp_path: Path):
    resp = _upload(client, "inventory.csv", b"col1,col2\n1,2\n")
    assert resp.status_code == 201
    body = resp.json()
    assert body["layout"] == "single_file"
    assert body["ready"] is True
    assert body["files"] == [{"filename": "inventory.csv", "size": 14, "label": None}]
    assert body["relative_data_dir"] == f"uploads/{body['upload_id']}"

    on_disk = tmp_path / "uploads" / body["upload_id"] / "inventory.csv"
    assert on_disk.read_bytes() == b"col1,col2\n1,2\n"
    assert not (tmp_path / "uploads" / body["upload_id"] / "inventory.csv.part").exists()


def test_get_upload_returns_the_same_state(client: TestClient):
    upload_id = _upload(client, "a.csv", b"data").json()["upload_id"]
    resp = client.get(f"/api/uploads/{upload_id}")
    assert resp.status_code == 200
    assert resp.json()["upload_id"] == upload_id


def test_get_unknown_upload_id_is_404(client: TestClient):
    assert client.get("/api/uploads/does-not-exist").status_code == 404


# ---------------- two-file uploads: labeling required for ready ----------------


def test_two_file_upload_is_not_ready_until_both_labeled(client: TestClient):
    first = _upload(client, "devices.csv", b"a,b\n1,2\n").json()
    upload_id = first["upload_id"]

    second = _upload(client, "vulns.csv", b"c,d\n3,4\n", upload_id=upload_id).json()
    assert second["layout"] == "two_file"
    assert second["ready"] is False
    assert {f["label"] for f in second["files"]} == {None}

    labeled_one = client.post(
        f"/api/uploads/{upload_id}/label", json={"filename": "devices.csv", "label": "inventory"}
    ).json()
    assert labeled_one["ready"] is False  # only one of two labeled

    labeled_two = client.post(
        f"/api/uploads/{upload_id}/label", json={"filename": "vulns.csv", "label": "findings"}
    ).json()
    assert labeled_two["ready"] is True
    by_name = {f["filename"]: f["label"] for f in labeled_two["files"]}
    assert by_name == {"devices.csv": "inventory", "vulns.csv": "findings"}


def test_label_can_be_supplied_inline_on_the_second_upload(client: TestClient):
    upload_id = _upload(client, "devices.csv", b"a,b\n1,2\n").json()["upload_id"]
    body = _upload(client, "vulns.csv", b"c,d\n3,4\n", upload_id=upload_id, label="findings").json()
    by_name = {f["filename"]: f["label"] for f in body["files"]}
    assert by_name["vulns.csv"] == "findings"


def test_both_files_cannot_share_the_same_label(client: TestClient):
    upload_id = _upload(client, "devices.csv", b"a,b\n1,2\n").json()["upload_id"]
    _upload(client, "vulns.csv", b"c,d\n3,4\n", upload_id=upload_id)

    client.post(f"/api/uploads/{upload_id}/label", json={"filename": "devices.csv", "label": "inventory"})
    resp = client.post(f"/api/uploads/{upload_id}/label", json={"filename": "vulns.csv", "label": "inventory"})
    assert resp.status_code == 400
    assert "already assigned" in resp.json()["detail"]


def test_unknown_label_value_is_refused(client: TestClient):
    upload_id = _upload(client, "a.csv", b"x").json()["upload_id"]
    resp = client.post(f"/api/uploads/{upload_id}/label", json={"filename": "a.csv", "label": "bogus"})
    assert resp.status_code == 400


def test_labeling_an_unknown_file_in_a_real_set_is_404(client: TestClient):
    upload_id = _upload(client, "a.csv", b"x").json()["upload_id"]
    resp = client.post(f"/api/uploads/{upload_id}/label", json={"filename": "nope.csv", "label": "inventory"})
    assert resp.status_code == 404


def test_labeling_in_an_unknown_upload_set_is_404(client: TestClient):
    resp = client.post("/api/uploads/does-not-exist/label", json={"filename": "a.csv", "label": "inventory"})
    assert resp.status_code == 404


# ---------------- refusals ----------------


def test_a_third_file_in_one_set_is_refused(client: TestClient):
    upload_id = _upload(client, "a.csv", b"1").json()["upload_id"]
    _upload(client, "b.csv", b"2", upload_id=upload_id)
    resp = _upload(client, "c.csv", b"3", upload_id=upload_id)
    assert resp.status_code == 400
    assert "at most" in resp.json()["detail"] or "already has" in resp.json()["detail"]


def test_uploading_to_an_unknown_upload_id_is_404(client: TestClient):
    resp = _upload(client, "a.csv", b"1", upload_id="does-not-exist")
    assert resp.status_code == 404


@pytest.mark.parametrize("filename", ["..", ".", "/", "///"])
def test_a_filename_that_sanitizes_to_empty_is_refused(client: TestClient, filename):
    """A literally empty filename never reaches this check at all --
    Starlette's own multipart handling treats it as no file sent (a 422
    before this route's body even runs). These are the realistic
    non-empty client-sent names that still reduce to "" once
    Path(...).name strips path separators and "."/".." components."""
    resp = client.post("/api/uploads", files={"file": (filename, b"1", "text/csv")})
    assert resp.status_code == 400


def test_re_uploading_the_same_filename_overwrites_content_and_resets_its_label(client: TestClient, tmp_path):
    upload_id = _upload(client, "devices.csv", b"a,b\n1,2\n").json()["upload_id"]
    _upload(client, "vulns.csv", b"c,d\n3,4\n", upload_id=upload_id)
    client.post(f"/api/uploads/{upload_id}/label", json={"filename": "devices.csv", "label": "inventory"})

    body = _upload(client, "devices.csv", b"new,content\n9,9\n", upload_id=upload_id).json()
    by_name = {f["filename"]: f for f in body["files"]}
    assert by_name["devices.csv"]["label"] is None  # reset, not carried forward
    assert by_name["devices.csv"]["size"] == len(b"new,content\n9,9\n")

    on_disk = tmp_path / "uploads" / upload_id / "devices.csv"
    assert on_disk.read_bytes() == b"new,content\n9,9\n"


# ---------------- sanitization ----------------


def test_path_traversal_in_filename_is_reduced_to_its_basename(client: TestClient, tmp_path: Path):
    resp = _upload(client, "../../evil.csv", b"payload")
    assert resp.status_code == 201
    body = resp.json()
    assert body["files"] == [{"filename": "evil.csv", "size": 7, "label": None}]

    escaped_path = tmp_path / "evil.csv"
    assert not escaped_path.exists()
    contained_path = tmp_path / "uploads" / body["upload_id"] / "evil.csv"
    assert contained_path.read_bytes() == b"payload"


# ---------------- size ceiling ----------------


def test_oversized_upload_is_refused_and_leaves_no_partial_file(client: TestClient, tmp_path, monkeypatch):
    monkeypatch.setenv(uploads_module.MAX_UPLOAD_BYTES_ENV, "10")
    resp = _upload(client, "big.csv", b"x" * 100)
    assert resp.status_code == 413

    # No upload set should have persisted a partial or final file for this.
    uploads_root = tmp_path / "uploads"
    leftover = list(uploads_root.rglob("big.csv*")) if uploads_root.exists() else []
    assert leftover == []


def test_upload_within_the_configured_ceiling_still_succeeds(client: TestClient, monkeypatch):
    monkeypatch.setenv(uploads_module.MAX_UPLOAD_BYTES_ENV, "1000")
    resp = _upload(client, "ok.csv", b"x" * 100)
    assert resp.status_code == 201


# ---------------- idempotency ----------------


def test_idempotency_key_returns_the_cached_response_without_a_second_upload(client: TestClient, tmp_path):
    headers = {"Idempotency-Key": "retry-key-1"}
    first = _upload(client, "a.csv", b"hello", headers=headers)
    second = _upload(client, "a.csv", b"hello", headers=headers)

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json() == second.json()

    uploads_root = tmp_path / "uploads"
    assert len(list(uploads_root.iterdir())) == 1  # only one upload set directory was ever created


def test_different_idempotency_keys_create_separate_sets(client: TestClient, tmp_path):
    first = _upload(client, "a.csv", b"hello", headers={"Idempotency-Key": "key-a"})
    second = _upload(client, "a.csv", b"hello", headers={"Idempotency-Key": "key-b"})

    assert first.json()["upload_id"] != second.json()["upload_id"]


# ---------------- registry unit tests (no HTTP) ----------------


def test_upload_registry_bounds_its_in_memory_history(tmp_path):
    registry = uploads_module.UploadRegistry(tmp_path, max_sets=2)
    ids = [registry.create_set().id for _ in range(3)]
    assert registry.get(ids[0]) is None  # evicted -- oldest first
    assert registry.get(ids[1]) is not None
    assert registry.get(ids[2]) is not None
    # Eviction is in-memory only -- every directory this registry ever
    # created for a set still exists on disk (see module docstring).
    assert all((tmp_path / i).is_dir() for i in ids)
