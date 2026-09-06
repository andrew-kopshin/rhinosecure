"""A narrow, mechanical grounding check for free prose: does a field
mention a CVE ID that contradicts the one real CVE the finding it was
written about is actually for?

CLAUDE.md's Safety and guardrails "Grounding validation" open item names
free prose (`RiskRecommendation.verdict_summary`/`narrative`,
`ResearchFinding.exploitation_summary`, `EnvironmentAssessment
.applicability_summary`, `tot.py`'s `ProposalOutput.proposal`/
`CritiqueOutput.justification`) as the piece `verify_scoring_matches_tool`/
`verify_research_matches_tool`/`verify_environment_matches_tool`/
`verify_constraint_matches_tool` cannot reach -- those all check
verbatim-copyable numeric/categorical/list fields against a tool's own
call_log result. Free-synthesized prose has no single ground-truth string
to diff against byte-for-byte, and this codebase has no LLM-judge
precedent to reach for instead: an LLM checking another LLM's prose would
be a second unreliable opinion, not a fix -- see CLAUDE.md's repeatedly
stated "the model never computes the number, only cites it" discipline,
already applied to `tot.CriticScores.aggregate` and to a future
execution-proposal's citation of real evidence.

**What this narrow check actually catches, and does not.** Every one of
the prose fields above is written about exactly ONE finding, which has
exactly one real `cve_id`. A prose field that mentions a DIFFERENT CVE ID
is essentially always a hallucination -- a finding's own narrative has no
legitimate reason to cite a different CVE by ID (a reference to a related
vulnerability would say so in words, not swap the identifier it's
supposed to be about). This is narrow by design: it catches "wrong
specific identifier," not "unsupported claim," "wrong number," or
"invented detail" -- those remain open, exactly as CLAUDE.md records.

**`hostname`/`finding_id` mention-checking were considered and
deliberately deferred, not built badly.** Neither has a single universal
shape to regex for the way a CVE ID does: `finding_id` formats vary by
ingest adapter ("F01" natively, "MDVMC-..." for Defender-shaped sources,
"VULN-..." for BluePeak), and a hostname string has no fixed pattern at
all. Checking either correctly would require passing the WHOLE fleet's
real identifiers into every check (to tell "mentions a real but wrong
one" apart from "mentions something that merely looks like one"), not
just the one finding's own evidence this module's function actually
receives -- a materially bigger, riskier piece of engineering than the
check below.

No I/O, no LLM call -- a pure regex-and-compare function, the same
"no external dependency" discipline `agents/prompt_safety.py` and
`remediation.py` already hold themselves to. Deliberately returns a set
rather than raising: each calling agent module re-raises through its own
existing mismatch type (`ResearchMismatchError`, `EnvironmentMismatchError`,
`ScoringMismatchError`, or `tot.py`'s `AgentOutputParseError` reuse for
the strategy-echo check) rather than this module inventing a new
exception type every call site's own retry seam would need to learn
about.
"""

from __future__ import annotations

import re

# The exact pattern this project's other CVE-recognizing code already
# uses (agents/chat.py's _CVE_MENTION_PATTERN, adapters/configured.py's
# _CVE_ID_PATTERN) -- unanchored and case-insensitive, to find a mention
# anywhere inside free-form prose rather than validate one whole field.
_CVE_MENTION_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def find_wrong_cve_mentions(text: str, real_cve_id: str) -> set[str]:
    """Returns every CVE ID `text` mentions OTHER than `real_cve_id` --
    an empty set if the only CVE ID mentioned (or none at all) is the
    real one. Case-insensitive on both sides, so a source that happens to
    store `real_cve_id` in a different case than the prose's own mention
    doesn't produce a false positive."""
    mentioned = {m.group(0).upper() for m in _CVE_MENTION_PATTERN.finditer(text)}
    return mentioned - {real_cve_id.upper()}
