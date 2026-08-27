# RhinoSecure — Progress Log

Factual, dated record of what changed and why. Not a design doc — see CLAUDE.md for the
current spec and rationale; this file is the history of how it got there.

## 2026-08-27

**KEV + EPSS wired into the threat term.** KEV and EPSS are treated as different kinds of
claim: EPSS is a model's probability estimate, KEV is CISA's record of confirmed exploitation.
EPSS sets the likelihood multiplier (`0.6 + epss`, range 0.6–1.6); KEV sets a **floor** under
it (`max(epss_multiplier, 1.5)`) instead of multiplying on top of it, so an observation can't
be diluted by — or compounded with — a prediction that disagrees with it. A KEV CVE the model
underrates gets pulled up to the floor; a KEV CVE the model already rates highly is left alone.

**Fixture repair: KEV and EPSS were both non-discriminating.** The original 15-finding fixture
was built from famous anchor CVEs (ProxyLogon, ZeroLogon, PrintNightmare, etc.). Checked
against the live feeds: 13/15 (87%) were KEV-listed and 14/15 (93%) had EPSS above 0.92 — both
signals near-saturated, so wiring them in would have added almost no spread. Added 9 real,
verified mundane Windows CVEs (outdated/superseded components, info disclosure, local privesc
requiring prior access), each checked live and kept only if EPSS < 0.05 and not KEV-listed.
Fixture is now 24 findings across 12 assets.

**Bucket rule: KEV disqualifies `accept`.** A KEV-listed finding can no longer land in
`accept` — confirmed exploitation and "we are fine with this" are incompatible. `is_kev` forces
at least the actionable tier; the existing compensating-control/patch-window logic still picks
`mitigate_monitor` vs `next_window` within it, unchanged. The one combination that logic can't
resolve honestly — KEV-listed, no compensating control, no patch window — has no truthful
bucket among the four remediation categories, so it's marked `contested` instead of forced into
one. Added as `Bucket.CONTESTED`, documented as the first concrete trigger for Slice 4's
Tree-of-Thought gate (not yet built).

**The contested rule found more than it was built for.** It was scoped against 4 findings that
were sitting in `accept`. Applied, it also caught `F11` (WKS-IT05, SMBGhost) and `F07`
(WKS-FIN12, Follina) — both already in `next_window`, both KEV-listed, both with no
compensating control and no patch window. `next_window` was silently implying they were
scheduled when nothing was. Neither finding was in the discussion that produced the rule; the
rule caught them anyway because the condition it checks (`is_kev` + no control + no window) is
what mattered, not the bucket a finding happened to start in.

**Live instance of why snapshotting matters.** `CVE-2019-1068` (on the fixture's `F15`, added
last session specifically to exercise `mitigate_monitor`) entered the CISA KEV catalog on
2026-08-26 — one day before this session — with a due date of 2026-08-29, a three-day window.
Mid-project, a fixture CVE picked for an unrelated reason became actively exploited with an
active remediation deadline. `data/snapshots/kev.json` is pinned to the version fetched this
session; without that, a rerun next week would silently produce different KEV/EPSS numbers for
the same fixture, breaking the reproducibility CLAUDE.md Section 4 requires.

**NVD wired: authoritative CVSS overrides scanner_severity.** `enrich/nvd.py` queries the v2.0
API per CVE with retry-with-backoff on 403/429 (real NVD throttling hit repeatedly while
fetching the fixture's 20 CVEs unauthenticated, and recovered every time). NVD's base_score
overrides the scanner's severity tier on disagreement, and provenance (which source, and
whether they disagreed) is recorded on every finding's rationale. 10 of 24 findings disagree.
`F14`'s risk climbs 1.99 → 30.62 (15.4x) once applied — the correction the earlier F14 decision
named. Bug caught along the way: NVD's metric arrays can hold two scorers (vendor CNA + NVD
itself) and aren't reliably ordered NVD-first; a naive `entries[0]` silently took Microsoft's
5.5/medium for ZeroLogon over NVD's own 10.0/critical. Caught by inspection, not by a test:
5.5/medium contradicted ZeroLogon's well-known real-world severity (an unauthenticated
domain-controller takeover), which is what prompted checking the raw response instead of
trusting the parsed value. Fixed to select by NVD's `"Primary"` tag instead of position.
Also corrected the risk-normalization ceiling (`MAX_SEVERITY_BASE`), which still assumed
severity topped out at 9.5 (the old scanner-tier proxy) even though NVD's real scores can
reach 10.0 — no finding was close enough to the old ceiling to have visibly clipped,
but it would have.

**Fixture correction: 10/24 scanner/NVD disagreements was too many to be deliberate.** `F16`-
`F24`'s `scanner_severity` values were assigned by hand for narrative variety when those rows
were added, not derived from anything real. 7 of the 9 turned out to disagree with NVD, all in
the same direction (NVD higher) — unexamined placeholder data, not a realistic scanner failure
mode. Corrected those 7 to match NVD. Left exactly three deliberate disagreements, each with a
specific reason: `F12` (under-called), `F14` (under-called, the designated bad-data case),
`F15` (over-called — the opposite direction, enrichment pulling a score down instead of up).
3/24 (12.5%) reads as a realistic scanner; 10/24 (42%) read as a broken one. No scoring output
changed — `_resolve_severity` was already using NVD's real score for all 7 regardless of what
the CSV said — confirmed the bucket distribution and every finding's risk score are unchanged.

**The thesis demonstrating itself.** Seven of those nine mundane findings (`F17`-`F23`) had
`scanner_severity` corrected up to 7.8/high once matched to NVD, and their risk scores rose
with it — up to roughly 10x (e.g. `F17`: 0.95 → 9.26). None crossed `ACTIONABLE_THRESHOLD`
(18); the highest landed at 10.32. Their EPSS stayed under 0.05 throughout, so the threat term
never moved enough to matter, regardless of how technically severe NVD rated them. This is
CLAUDE.md Section 1's thesis — "CVSS alone is an insufficient prioritization signal" — playing
out on real data rather than being asserted: a high-severity, low-exploitation-probability
finding correctly stays low priority, because Risk = Threat × Impact means a strong score on
one axis can't rescue a weak one on the other.
