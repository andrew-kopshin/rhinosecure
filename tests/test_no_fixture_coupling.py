"""Enforces the CLAUDE.md rule that no component may assume its input is
synthetic: schema.py, ingest.py, scoring.py, and every ingest adapter under
adapters/ must never reference a specific asset_id, cve_id, or finding_id
literal. If this test needs to be touched to make a change pass, the change
is almost certainly encoding fixture-specific behavior into logic that must
stay general.
"""

import re
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src" / "rhinosecure"
GUARDED_FILES = ["schema.py", "ingest.py", "scoring.py"] + sorted(
    str(p.relative_to(SRC_DIR)) for p in (SRC_DIR / "adapters").glob("*.py")
)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+")
ASSET_ID_PATTERN = re.compile(r"\bA\d{2}\b")
FINDING_ID_PATTERN = re.compile(r"\bF\d{2}\b")


def test_no_hardcoded_fixture_identifiers():
    offenders = []
    for filename in GUARDED_FILES:
        text = (SRC_DIR / filename).read_text(encoding="utf-8")
        for pattern in (CVE_PATTERN, ASSET_ID_PATTERN, FINDING_ID_PATTERN):
            for match in pattern.finditer(text):
                offenders.append(f"{filename}: found {match.group()!r}")
    assert not offenders, "fixture-specific identifiers leaked into general logic:\n" + "\n".join(offenders)
