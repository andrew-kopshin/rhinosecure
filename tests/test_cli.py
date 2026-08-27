from pathlib import Path

from rhinosecure.cli import main, run

DEMO_DIR = Path(__file__).resolve().parents[1] / "data" / "demo"


def test_offline_flag_is_accepted_and_does_not_error():
    assert main(["run", "--data", "demo", "--seed", "42", "--offline"]) == 0


def test_offline_flag_does_not_change_output_in_slice_1():
    """Slice 1 makes no network calls, so --offline has nothing to gate yet
    -- it must be a pure no-op on the ranked output until Slice 2 wires
    enrichment through SnapshotCache."""
    online = run(DEMO_DIR, seed=42, offline=False)
    offline = run(DEMO_DIR, seed=42, offline=True)
    assert [(s.finding_id, s.risk_score, s.bucket) for s in online] == [
        (s.finding_id, s.risk_score, s.bucket) for s in offline
    ]
