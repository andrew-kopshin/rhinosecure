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

## 2026-09-01

**ATT&CK wired in, two-tier: confirmed feeds the score, candidate stays informational.**
`enrich/attack.py` fetches the Enterprise STIX bundle and filters to Windows-platform
techniques, but there is no direct CVE → technique edge anywhere in ATT&CK's own data — that
bridge normally runs through CAPEC/CWE, which CLAUDE.md Section 11 does not name as a source
for this project. Two tiers instead: **confirmed**, when a CVE is explicitly named in an
ATT&CK "uses" relationship's procedure-example text (a tracked group or malware/tool STIX
object documented exploiting it — e.g. HAFNIUM's relationship to T1190 cites CVE-2021-26855 by
name), and **candidate**, IDF-weighted keyword overlap between the finding's product/evidence
text and technique name+description, for CVEs no procedure example happens to mention. Only
confirmed matches feed `ThreatInputs.attack_prevalence`; candidates are attached to the finding
and shown in rationale but never move a score. Candidate matching is a hand-tuned stand-in for
the MMR-reranked vector retrieval CLAUDE.md Section 4 actually specifies for ATT&CK prose —
`retrieval/vector.py`/`mmr.py` don't exist yet — and lexical overlap can't reliably distinguish
"rare because specific" from "rare because unusual phrasing," so it isn't confident enough
evidence for a deterministic score the way an explicit procedure-example citation is.

**Bundle filtered before it touches disk, not after.** The raw Enterprise bundle is 53,835,637
bytes (~51MB) and covers every platform (macOS, Linux, cloud, network devices, PRE) and STIX
object type (mitigations, campaigns, data sources) this project has no use for. Committing it
verbatim, the way kev.py/epss.py/nvd.py cache their raw responses, would have bloated the repo
with data nothing here reads. `_fetch_and_filter` does the filtering inline — Windows platform,
not revoked, not deprecated — before anything is written, so only the reduced structure is
persisted: `data/snapshots/attack/enterprise-windows.json`, 765,060 bytes (~747KB), 474 of the
bundle's 858 total techniques, plus a 161-entry CVE-mention index built by regex-scanning kept
relationships' descriptions. ~70x smaller than the source, and the only artifact this project
ever reads back.

**Real split: 7 confirmed / 14 candidate / 3 none, across the 24-finding fixture.** Three
techniques got confirmed matches, each because a famous, heavily-tracked anchor CVE is
well-documented enough for ATT&CK's own procedure examples to name it: T1190 Exploit
Public-Facing Application (`CVE-2021-26855`/`CVE-2021-31207`, ProxyLogon/ProxyShell — `F01`,
`F02`, `F03`, `F13`), T1210 Exploitation of Remote Services (`CVE-2020-1472`, ZeroLogon —
`F04`), and T1203 Exploitation for Client Execution (`CVE-2022-30190`, Follina — `F07`, `F08`).
The remaining 14 findings got only unconfirmed keyword candidates, and 3 (`F10`, `F23`, `F24`)
got nothing above the candidate-tier confidence bar at all. Bucket distribution is unchanged
from before this session (`patch_now=1, next_window=8, contested=3, mitigate_monitor=3,
accept=9`) — ATT&CK prevalence is refining risk scores within buckets, not reshuffling them.

**Limitation: the confirmed tier mostly re-confirms what KEV/EPSS already said.** Checked the
four distinct CVEs behind the 7 confirmed matches against the fixture's own KEV/EPSS snapshots:
all four are KEV-listed, and all four carry EPSS ≥ 0.992 — the same near-saturated territory
the 2026-08-27 entry above already documented for the fixture's famous anchors ("13/15 KEV,
14/15 EPSS > 0.92"). ATT&CK's confirmed tier is not surfacing new information about which
findings matter; it is re-deriving, from a third independent-in-principle source, the same
"this one is famous" signal KEV and EPSS were already saturated on. That is a real property of
public threat-intel sources, not a mapping bug: KEV, EPSS, and ATT&CK procedure-example
documentation all preferentially track whichever CVEs are well-documented, so three sources
that each individually look independent correlate heavily in practice once a CVE is famous
enough for all three to have noticed it. It is also, after the fact, a second reason the
confirmed/candidate split was the right call beyond the CAPEC/CWE-bridge argument above: on this
fixture, confirmed-tier ATT&CK data added least exactly where the score already had the most
reason to be high, and the candidate tier — informational rather than score-moving — is where
the mundane, non-KEV, low-EPSS findings' only ATT&CK context actually shows up.
