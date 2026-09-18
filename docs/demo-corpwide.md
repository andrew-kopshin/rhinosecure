# Corpwide demo: same CVE, three verdicts

`data/corpwide/corpwide_scan_14.csv` is a hand-authored flat scanner export: 14 findings, 10 assets,
23 columns, one file. It exists to show one CVE (CVE-2021-44228, KEV-listed, CVSS 10.0) landing
differently on three assets, and to exercise every bucket.

All commands run from the repo root. Use the module invocation (`rhino.exe` is blocked by Smart App
Control on this machine).

```powershell
cd C:\Users\akops\rhinosecure
$py = ".\.venv312\Scripts\python.exe"
```

## 1. Profile (no LLM, writes nothing)

```powershell
& $py -m rhinosecure.cli adapt probe corpwide
```

Expect: utf-8, delimiter `,`, 14 rows, 23 columns, no blank cells except Patch Window (2/14),
Patch Restrictions (3/14) and Compensating Controls (12/14), which are blank on purpose.

## 2. Propose (real LLM call, about $0.15-0.30)

```powershell
& $py -m rhinosecure.cli adapt propose corpwide --data corpwide
```

`--data` is required here and on confirm. It is never defaulted: the contract name and the data
directory are different things, and a signature covers specific bytes.

Expect: every slot mapped, grounding clean, `Wrote ...corpwide.json (vN, review.state=proposed)`.

The model is not deterministic. A run may leave a slot unresolved (the two earlier runs did, before
the fixture had columns for `patch_restrictions` and `os_build`). If it does, the report names the
slot. Resolve it in `out/propose_corpwide.json`, then re-run with `--from-proposal
out/propose_corpwide.json`, or use the browser resolve-slots form. Note that `--from-proposal`
attributes every slot to a human, by design.

Re-proposing over a signed contract needs `--overwrite-confirmed`.

## 3. Review without signing

```powershell
& $py -m rhinosecure.cli adapt rereview corpwide --data corpwide
```

Read the dialect line and the "Attestations" section. If the model set `asset_grouping.union_fields`
(it set `compensating_controls` once), an attestation named `union` is required.

## 4. Confirm (a signed human act)

```powershell
& $py -m rhinosecure.cli adapt confirm corpwide --data corpwide --by "<your real name>" --attest union="<your own sentence>"
```

- `--by` is never inferred, and whatever string you type is recorded literally. `"Your Name"` and
  `"<you>"` are recorded as signatures.
- Every `--attest` must be a sentence a person wrote. Nothing is generated. Drop the flag if review
  says no attestation is required.

## 5. Run

```powershell
& $py -m rhinosecure.cli run --data corpwide --adapter-config corpwide --seed 42 --offline
```

`--offline` is safe: the NVD and EPSS snapshots for every CVE in this file are cached under
`data/snapshots/`, and the KEV snapshot is pinned to 2026-08-27 on purpose (runs must stay
reproducible; each result's `sources[].retrieved_at` in the export shows the date).

Expect 14 findings: `patch_now` 2, `next_window` 9, `mitigate_monitor` 1, `contested` 1, `accept` 1
(contested 1/14, 7.1%). This was verified in memory against the unsigned contract before signing.

## 6. The three CVE-2021-44228 findings

```powershell
& $py -m rhinosecure.cli run --data corpwide --adapter-config corpwide --seed 42 --offline --explain --export out\export_corpwide.json
```

| Finding | Asset | Criticality | Exposed | Data | Risk | Bucket |
|---|---|---|---|---|---|---|
| F-0001 | web-portal-01 | 4 | yes | regulated | 81.83 | patch_now |
| F-0002 | sql-fin-01 | 5 | no | regulated | 48.05 | next_window |
| F-0003 | dev-sandbox-07 | 1 | no | public | 11.23 | next_window |

Risk = Threat x Impact / 259.2 x 100. Threat is identical for all three except internet exposure
(x1.35 vs x0.7), which is why the portal outranks the database despite lower criticality. The
database and the sandbox share a Threat score exactly, so their whole gap comes from Impact
(0.9625 vs 0.225). The sandbox is `next_window` rather than `accept` because a KEV-listed finding
can never be accepted and its `Anytime` window counts as a declared window.

## Bucket coverage, by design

| Bucket | Finding | Why |
|---|---|---|
| patch_now | F-0001, F-0006 | risk >= 70 |
| mitigate_monitor | F-0008 (vpn-gw-01) | KEV, a compensating control, no declared patch window |
| contested | F-0009 (wks-hr-114) | KEV, no control, no declared patch window: no honest bucket |
| accept | F-0014 (k8s-cp-01) | not KEV, risk below 18 |
| next_window | the rest | actionable, has a declared window |
