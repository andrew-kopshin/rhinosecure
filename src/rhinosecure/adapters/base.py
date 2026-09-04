"""Ingest adapters: the seam between a source format and the native
Asset/Finding schema.

CLAUDE.md Section 1 ("Synthetic data is a scaffold, not the design") sets the
contract this package exists to honor: swapping in a real scanner export
should require a new ingest adapter and nothing else. An adapter reads a
source format's own files, with its own column names, and hands rows to the
same `Asset` / `Finding` models everything downstream already consumes --
scoring.py, enrich/, agents/ never learn which format a record came from.
`ingest.py`'s native loaders are one adapter (`adapters/native.py`);
`adapters/defender.py` is the first real-export one.

Two rules every adapter follows, both consequences of the same Section 1
guardrail (real vulnerability data is a map of where an organization is
weak, so silently mis-mapping it is worse than refusing it):

1. **Fail loudly on unmappable input; never guess.** A column the mapping
   needs but the file lacks, a platform value the adapter has no entry for,
   a severity outside the source's own vocabulary, a finding whose host is
   absent from the inventory -- each raises `AdapterError` naming the file,
   the row, and the reason, ideally all of them at once so the operator can
   fix the export in one pass. Nothing is coerced into a plausible value,
   and nothing is dropped on the floor.

2. **Represent what the source has no concept of explicitly.** This is the
   `not_collected` mechanism below.

Fields the source format has no concept of
-------------------------------------------
A real scanner export carries technical facts -- host identity, OS, CVE,
severity, software -- and little or none of the business context RhinoSecure's
Impact axis is built on. Microsoft Defender Vulnerability Management, for
example, exports no maintenance window, no compensating controls, no
environment tier, no data-sensitivity classification, and no role. Every
Defender asset would therefore arrive with a blank `patch_window` -- and the
schema already gives that blank a meaning: "no declared scheduling
restriction" (CLAUDE.md Section 3), which `bucket_for` reads as "may be
patched at any time". For a Defender asset the blank means something
different: "nobody asked". Section 3's open item named exactly this
ambiguity as the thing that would bite once real data replaced the fixture.

The representation chosen here separates the *value* from the *claim*:

- The value stays whatever the schema already treats as absent -- "" for
  the free-text fields -- so nothing downstream changes: `bucket_for`,
  `has_patch_window`, `compensating_control_list`, and the constraint
  overlay all keep reading the field exactly as they do for a native asset,
  and the demo fixture's output stays byte-identical (Section 8 rule 2).
- The claim moves into a separate, machine-readable field on the record:
  `Asset.not_collected` / `Finding.not_collected`, the set of schema field
  names the source had no concept of (or left blank for that one row). A
  blank `patch_window` with `"patch_window" in asset.not_collected` means
  "unknown"; the same blank without it means "none declared". The two are
  now distinguishable everywhere the record travels -- `rhino run` prints a
  data-gap summary and, under --explain, a per-finding note -- instead of
  collapsing into one silent blank.

Why not a sentinel value ("<not collected>") in the field itself: any
non-blank `patch_window` flips `has_patch_window` to True and any non-blank
`compensating_controls` manufactures a control, so a sentinel would change
bucket verdicts and require every consumer to learn to skip it. Why not
`None`: a CSV cell cannot distinguish None from "", so the native loader
would have had to decide which one a blank means, reintroducing the
ambiguity one layer down.

The enumerated Impact inputs (`role`, `environment`, `data_sensitivity`,
`criticality`) have no absent encoding at all -- `scoring.py` indexes its
weight tables by them directly -- so a record must carry *some* member of
the vocabulary. `NOT_COLLECTED_DEFAULTS` fixes which one, uniformly, for
every adapter: the modal enterprise value, deliberately neither the best nor
the worst case. Worst-casing (every unknown server a domain controller in a
regulated production environment) would flood `patch_now` uniformly and
teach a reader to distrust the ranking; best-casing would hide risk, the one
failure mode a security tool must not have. The modal value is the honest
prior given only "a Windows device in an enterprise fleet", and because it
is the same for every record of a format, it shifts every finding's Impact
by the same constant rather than reordering them. Whatever the default, the
field name sits in `not_collected`, so the plan says which numbers rest on a
default and the operator knows which to supply. The fill-in path already
exists for the operational fields: `rhino constraint add` persists a patch
window, restriction, or compensating control per asset (CLAUDE.md Section 7)
and the overlay is applied on the next agents run. Role, environment, and
data sensitivity have no such path yet -- see CLAUDE.md Section 3's open
items.

`role` is the one default that depends on the record: a client OS
(Windows 10/11) is a workstation-class machine, so `workstation` is nearly
a fact rather than a prior; a server OS says nothing about whether the box
is a domain controller or a print server, and `file` is the most generic
server role in the vocabulary (blast radius 0.55, mid-table). Both are still
marked `not_collected` -- the OS class chose the default, the source never
said so. Adding a dedicated `server` role would be the cleaner encoding but
needs a weight in `scoring.ROLE_BLAST_RADIUS`, which is a scoring change
and out of an adapter's remit.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Collection, Iterator
from pathlib import Path
from typing import ClassVar

from rhinosecure.ingest import IngestError, IngestStats
from rhinosecure.schema import Asset, Finding


class AdapterError(IngestError):
    """Input an adapter refuses to map. Subclasses IngestError so cli.py's
    existing "ingest error" handling covers it; the message always names
    the file and, where a row is at fault, the row number and reason."""


# Value a field takes when the source format has no concept of it (or left
# the cell blank). Free-text fields use the schema's own absent encoding;
# enumerated Impact inputs use the modal enterprise value -- see the module
# docstring for why modal, not worst-case. `role` is not here: it depends on
# the record's OS class (ROLE_DEFAULT_BY_OS_CLASS).
#
# "os" was added alongside "os_build" for adapters/bluepeak.py: unlike
# Defender (whose whole per-device axis is a Windows OS platform), a
# pre-enriched, multi-platform source can have no reliable per-asset OS
# signal at all -- Defender never needed a default here because it always
# has one.
NOT_COLLECTED_DEFAULTS: dict[str, object] = {
    # Asset
    "business_function": "",
    "owner": "",
    "patch_window": "",
    "patch_restrictions": "",
    "compensating_controls": "",
    "os": "",
    "os_build": "",
    "environment": "prod",
    "data_sensitivity": "internal",
    "criticality": 3,
    "internet_exposed": False,
    # Finding
    "detected_date": "",
    "version": "",
    "port": "",
    "service": "",
}

# See the module docstring's last paragraph.
ROLE_DEFAULT_BY_OS_CLASS: dict[str, str] = {
    "client": "workstation",
    "server": "file",
}


class IngestAdapter(ABC):
    """One source format. `format` is the `--format` value; the two
    filenames are what the adapter expects to find under `--data`'s
    directory. `stats` is reset by each load call and filled in as its
    iterator is consumed -- a streaming loader cannot know how many
    duplicate rows it collapsed until the stream is exhausted.

    `provides_enrichment`: True only for a source whose export already
    carries CVSS/exploitation/technique data of its own -- Finding's it
    yields populate `Finding.source_enrichment` (schema.py). `False`
    (native, defender) means the caller must run the live
    KEV/EPSS/NVD/ATT&CK lookups (`ingest.attach_threat_signals`) to get
    those signals at all; `True` (adapters/bluepeak.py) means the caller
    should skip that entirely -- both the bulk KEV/ATT&CK loads and the
    per-CVE lookups would be pure overhead against a source whose CVE IDs
    don't resolve anywhere live -- and call `ingest.attach_source_enrichment`
    instead. A run-level switch, not a per-finding one, so a format either
    is or isn't this shape; see adapters/bluepeak.py."""

    format: ClassVar[str]
    assets_filename: ClassVar[str]
    findings_filename: ClassVar[str]
    provides_enrichment: ClassVar[bool] = False

    def __init__(self) -> None:
        self.stats = IngestStats()

    @abstractmethod
    def load_assets(self, path: Path) -> Iterator[Asset]:
        """Every asset in the inventory file. May consume the whole file
        before yielding (the inventory is the small, indexed side of the
        join -- see ingest.load_asset_index); must never hold findings."""

    @abstractmethod
    def load_findings(self, path: Path, asset_ids: Collection[str]) -> Iterator[Finding]:
        """Findings, lazily. `asset_ids` is the inventory just loaded, so an
        adapter that wants to report every orphaned finding at once (rather
        than let ingest.join raise on the first) can check membership."""
