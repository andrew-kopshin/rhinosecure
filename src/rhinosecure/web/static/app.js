"use strict";

/* RhinoSecure plan viewer -- vanilla JS, no build step, no framework.
 * Fetches /api/export once, renders every tab from that one payload.
 * The export JSON is the sole source of truth: this file never fabricates
 * a value that isn't in the payload -- an absent/null/empty field always
 * renders an honest empty state, never a guess. */

const BUCKET_ORDER = [
  "patch_now",
  "next_window",
  "mitigate_monitor",
  "accept",
  "contested",
  "deferred_capacity",
];
const BUCKET_LABELS = {
  patch_now: "Patch Now",
  next_window: "Next Window",
  mitigate_monitor: "Mitigate & Monitor",
  accept: "Accept",
  contested: "Contested",
  deferred_capacity: "Deferred (Capacity)",
};

const STAGE_ORDER = ["ingest", "enrichment", "scoring", "agents", "tot"];
const STAGE_LABELS = {
  ingest: "Ingest",
  enrichment: "Enrichment",
  scoring: "Scoring",
  agents: "Agents",
  tot: "Tree-of-Thought",
};

const AXIS_ORDER = [
  "risk_reduction",
  "operational_cost",
  "constraint_compliance",
  "evidence_strength",
  "contradicting_evidence",
];
const AXIS_LABELS = {
  risk_reduction: "Risk reduction",
  operational_cost: "Operational cost",
  constraint_compliance: "Constraint compliance",
  evidence_strength: "Evidence strength",
  contradicting_evidence: "Contradicting evidence",
};

const STRATEGY_LABELS = {
  emergency_change: "Emergency change",
  establish_window: "Establish window",
  build_control: "Build control",
};
const TERMINATION_LABELS = {
  clear_winner: "clear winner",
  depth_limit: "depth limit",
  exhausted_evidence: "exhausted evidence",
};

/* job substrate (web/jobs.py) -- vocabulary is per job kind; this is
 * constraint_submit's. "seeding" only ever appears on the very first job
 * against a fresh server process (web/jobs.py's PlanState.seed). */
const JOB_STAGE_LABELS = {
  seeding: "Seeding the plan (first run only)",
  interpreting: "Interpreting your constraint",
  persisting: "Recording the constraint",
  research: "Researching CVE evidence",
  environment: "Mapping to the fleet",
  risk: "Scoring",
  replanning: "Re-scoring the affected finding(s)",
  computing: "Recomputing capacity allocation",
  exporting: "Refreshing the plan",
};

function jobStageLabel(stage) {
  if (!stage) return "Starting";
  if (stage.startsWith("tot:")) {
    const frac = stage.split(":")[1];
    return `Resolving contested finding(s) via Tree-of-Thought (${esc(frac)})`;
  }
  return JOB_STAGE_LABELS[stage] || esc(stage);
}

function esc(value) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

function bucketLabel(b) {
  return BUCKET_LABELS[b] || esc(b);
}

/* One line for a FindingDelta or CapacityDelta whose `changed` flag is
 * true -- always shows the risk score alongside the bucket, since a
 * bucket can stay identical while the score moves (a compensating
 * control decaying impact without crossing a threshold, say) and a
 * bucket-only summary would then read as if nothing happened. */
function deltaSummary(d) {
  const before = d.before_bucket || d.original_bucket;
  const after = d.after_bucket || d.effective_bucket;
  const beforeLabel =
    d.before_risk_score != null ? `${bucketLabel(before)} (${d.before_risk_score.toFixed(1)})` : bucketLabel(before);
  const afterLabel =
    d.after_risk_score != null
      ? `${bucketLabel(after)} (${d.after_risk_score.toFixed(1)})`
      : d.risk_score != null
      ? `${bucketLabel(after)} (${d.risk_score.toFixed(1)})`
      : bucketLabel(after);
  return `${esc(d.finding_id)}: ${beforeLabel} → ${afterLabel}`;
}

function strategyLabel(s) {
  return STRATEGY_LABELS[s] || esc(s);
}

function terminationLabel(t) {
  return TERMINATION_LABELS[t] || esc(t);
}

function baseName(p) {
  if (!p) return "";
  const parts = String(p).split(/[\\/]/);
  return parts[parts.length - 1] || p;
}

function formatTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return esc(iso);
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function showError(message) {
  const el = document.getElementById("error-banner");
  el.textContent = message;
  el.hidden = false;
}

/* ---------------- tabs ---------------- */

function setupTabs() {
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });
}

function switchTab(name) {
  document.querySelectorAll(".tab-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.tab === name);
  });
  document.querySelectorAll(".tab-panel").forEach((p) => {
    p.classList.toggle("active", p.id === `tab-${name}`);
  });
}

/* ---------------- header + sidebar ---------------- */

function renderRunMeta(data) {
  const r = data.run;
  const el = document.getElementById("run-meta");
  el.innerHTML = `
    <span class="meta-item"><span class="meta-label">Data</span>${esc(baseName(r.data_dir))}</span>
    <span class="meta-item"><span class="meta-label">Format</span>${esc(r.format)}</span>
    <span class="meta-item"><span class="meta-label">Seed</span>${esc(r.seed)}</span>
    <span class="meta-item"><span class="meta-label">Mode</span>${r.agents ? "agents" : "deterministic"}${r.offline ? " · offline" : ""}</span>
    <span class="meta-item"><span class="meta-label">Generated</span>${formatTime(data.generated_at)}</span>
  `;
}

function renderPipeline(data) {
  const ol = document.getElementById("pipeline-stages");
  ol.innerHTML = STAGE_ORDER.map((key) => {
    const stage = data.pipeline[key] || { status: "not_run", detail: "" };
    const statusClass = `status-${esc(stage.status || "not_run")}`;
    return `
      <li class="stage">
        <div class="stage-head">
          <span class="stage-dot ${statusClass}"></span>
          <span class="stage-name">${STAGE_LABELS[key] || esc(key)}</span>
          <span class="stage-status ${statusClass}">${esc((stage.status || "not_run").replace("_", " "))}</span>
        </div>
        <p class="stage-detail">${esc(stage.detail)}</p>
      </li>
    `;
  }).join("");
}

/* ---------------- overview ---------------- */

function renderOverview(data) {
  const el = document.getElementById("tab-overview");
  const dist = data.summary.bucket_distribution;
  const total = data.summary.total_findings || 0;
  const maxCount = Math.max(1, ...BUCKET_ORDER.map((b) => dist[b] || 0));

  const bars = BUCKET_ORDER.map((b) => {
    const count = dist[b] || 0;
    const pct = Math.round((count / maxCount) * 100);
    return `
      <div class="bucket-row">
        <span class="bucket-label bucket-${b}">${bucketLabel(b)}</span>
        <div class="bucket-bar-track"><div class="bucket-bar-fill bucket-${b}" style="width:${pct}%"></div></div>
        <span class="bucket-count">${count}</span>
      </div>
    `;
  }).join("");

  const cr = data.summary.contested_rate;
  const gapsHtml = renderDataGaps(data.summary.data_gaps, data.provenance);
  const usageHtml = renderUsageSummary(data.usage, data.run.agents);
  const provenanceHtml = renderProvenance(data.provenance);

  el.innerHTML = `
    <div class="card">
      <h3>Bucket distribution</h3>
      <div class="bucket-chart">${bars}</div>
      <p class="total-note">${total} finding(s) total</p>
    </div>
    <div class="card">
      <h3>Contested rate</h3>
      <p class="stat-line">
        <span class="stat-big">${cr.contested}/${cr.total}</span>
        <span class="stat-pct">(${cr.pct.toFixed(1)}%)</span>
      </p>
      <p class="hint">CLAUDE.md Section 6 targets roughly 1% at fleet scale; a small fixture-sized run is expected to read higher than that.</p>
    </div>
    <div class="card">
      <h3>Data gaps</h3>
      ${gapsHtml}
    </div>
    ${provenanceHtml}
    ${usageHtml}
  `;
}

function shortHash(s) {
  if (!s) return "";
  return s.length > 20 ? `${s.slice(0, 18)}…` : s;
}

function renderProvenance(prov) {
  if (!prov) {
    return `
      <div class="card">
        <h3>Mapping provenance</h3>
        <p class="empty-note">Built-in adapter — no reviewed contract behind this run.</p>
      </div>
    `;
  }

  const drift = prov.scale_drift
    ? `<p class="gap-note">
        This mapping was <strong>confirmed</strong> against ${prov.scale_drift.signed_assets} asset(s) and
        ${prov.scale_drift.signed_findings} finding(s), but this run <strong>loaded</strong>
        ${prov.scale_drift.loaded_assets} and ${prov.scale_drift.loaded_findings}. A signature covers the
        mapping, not the data volume — this can be expected if the source has simply grown since it was
        reviewed, but if the <em>shape</em> of the data has changed, re-review the contract
        (<code>rhino adapt rereview</code>) before trusting this run's numbers.
      </p>`
    : "";

  return `
    <div class="card">
      <h3>Mapping provenance</h3>
      <p class="stat-line">Contract <code>${esc(prov.format)}</code> v${esc(prov.version)}</p>
      <p class="hint">Confirmed ${formatTime(prov.confirmed_at)} by ${esc(prov.confirmed_by)}</p>
      ${drift}
      <p class="hint">
        content <code title="${esc(prov.content_digest)}">${esc(shortHash(prov.content_digest))}</code>
        · decision <code title="${esc(prov.decision_digest)}">${esc(shortHash(prov.decision_digest))}</code>
      </p>
    </div>
  `;
}

function renderDataGaps(gaps, prov) {
  const assetGapEntries = Object.entries(gaps.asset_gaps || {}).sort((a, b) => b[1] - a[1]);
  const findingGapEntries = Object.entries(gaps.finding_gaps || {}).sort((a, b) => b[1] - a[1]);
  const hasGaps =
    assetGapEntries.length > 0 ||
    findingGapEntries.length > 0 ||
    gaps.duplicate_assets_collapsed > 0 ||
    gaps.duplicate_findings_collapsed > 0;
  const flag = prov ? `--adapter-config ${gaps.format}` : `--format ${gaps.format}`;

  if (!hasGaps) {
    return `<p class="empty-note">No data gaps -- every field this run needed was collected from the source (${esc(flag)}).</p>`;
  }

  const assetCol = assetGapEntries.length
    ? `<div><h4>Asset fields not collected</h4><ul class="gap-list">${assetGapEntries
        .map(([f, c]) => `<li><code>${esc(f)}</code> — ${c}/${gaps.assets_total} asset(s)</li>`)
        .join("")}</ul></div>`
    : "";
  const findingCol = findingGapEntries.length
    ? `<div><h4>Finding fields not collected</h4><ul class="gap-list">${findingGapEntries
        .map(([f, c]) => `<li><code>${esc(f)}</code> — ${c}/${gaps.findings_total} finding(s)</li>`)
        .join("")}</ul></div>`
    : "";

  const dupeNote =
    gaps.duplicate_assets_collapsed || gaps.duplicate_findings_collapsed
      ? `<p class="dupe-note">Collapsed ${gaps.duplicate_findings_collapsed} duplicate finding row(s) and ${gaps.duplicate_assets_collapsed} duplicate asset row(s) at ingest.</p>`
      : "";

  return `<div class="gap-columns">${assetCol}${findingCol}</div>${dupeNote}`;
}

function renderUsageSummary(usage, agentsRan) {
  if (!agentsRan) {
    return `
      <div class="card">
        <h3>LLM usage</h3>
        <p class="empty-note">Deterministic run — no LLM calls were made (scoring.py stays LLM-free by design).</p>
      </div>
    `;
  }

  const stages = ["research", "environment", "risk", "tot"];
  let totalTokens = 0;
  const rows = stages
    .map((s) => {
      const u = usage ? usage[s] : null;
      if (!u) {
        return `<tr><td>${s}</td><td colspan="2" class="empty-note">not run</td></tr>`;
      }
      totalTokens += u.total_tokens || 0;
      return `<tr><td>${s}</td><td>${(u.total_tokens || 0).toLocaleString()}</td><td>${u.successful_requests || 0}</td></tr>`;
    })
    .join("");

  return `
    <div class="card">
      <h3>LLM usage</h3>
      <table class="usage-table">
        <thead><tr><th>Stage</th><th>Tokens</th><th>Requests</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <p class="total-note">${totalTokens.toLocaleString()} tokens total across all stages</p>
    </div>
  `;
}

/* ---------------- findings ---------------- */

function renderFindings(data) {
  const el = document.getElementById("tab-findings");
  const findings = data.findings;

  if (!findings.length) {
    el.innerHTML = `<p class="empty-note">No findings in this export.</p>`;
    return;
  }

  const rows = findings
    .map((f, i) => `
      <tr class="finding-row" data-idx="${i}">
        <td><code>${esc(f.finding_id)}</code></td>
        <td>${esc(f.cve_id)}</td>
        <td>${esc(f.hostname)}</td>
        <td><span class="bucket-pill bucket-${esc(f.bucket)}">${bucketLabel(f.bucket)}</span></td>
        <td class="num">${f.risk_score.toFixed(1)}</td>
        <td>${f.has_tot ? '<span class="tot-flag" title="Ran through Tree-of-Thought">ToT</span>' : ""}</td>
      </tr>
      <tr class="finding-detail-row" data-idx="${i}" hidden><td colspan="6"></td></tr>
    `)
    .join("");

  el.innerHTML = `
    <table class="findings-table">
      <thead>
        <tr><th>Finding</th><th>CVE</th><th>Host</th><th>Bucket</th><th>Risk</th><th></th></tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;

  el.querySelectorAll(".finding-row").forEach((row) => {
    row.addEventListener("click", () => toggleFindingDetail(row, findings[Number(row.dataset.idx)]));
  });
}

function toggleFindingDetail(row, finding) {
  const detailRow = row.nextElementSibling;
  const reopening = detailRow.hidden;

  document.querySelectorAll(".finding-detail-row").forEach((r) => {
    r.hidden = true;
    r.querySelector("td").innerHTML = "";
  });
  document.querySelectorAll(".finding-row").forEach((r) => r.classList.remove("open"));

  if (!reopening) return;

  detailRow.hidden = false;
  row.classList.add("open");
  detailRow.querySelector("td").innerHTML = findingDetailHtml(finding);

  const link = detailRow.querySelector(".jump-to-contested");
  if (link) link.addEventListener("click", (e) => { e.preventDefault(); switchTab("contested"); });
}

function findingDetailHtml(f) {
  const rationale = f.rationale.map((r) => `<li>${esc(r)}</li>`).join("");

  const sources = f.sources.length
    ? `<table class="sources-table">
        <thead><tr><th>Source</th><th>Key</th><th>Retrieved</th></tr></thead>
        <tbody>${f.sources
          .map(
            (s) =>
              `<tr><td>${esc(s.source)}</td><td>${s.key ? esc(s.key) : '<span class="dim">(bulk feed)</span>'}</td><td>${formatTime(s.retrieved_at)}</td></tr>`
          )
          .join("")}</tbody>
      </table>`
    : `<p class="empty-note">No cached source records found for this CVE.</p>`;

  const constraintsApplied = f.constraints_applied.length
    ? `<ul class="tag-list">${f.constraints_applied.map((c) => `<li>${esc(c)}</li>`).join("")}</ul>`
    : `<p class="empty-note">None</p>`;

  const cited = f.cited_text.length
    ? `<ul class="tag-list">${f.cited_text.map((c) => `<li>${esc(c)}</li>`).join("")}</ul>`
    : `<p class="empty-note">None recorded</p>`;

  const gapFields = [...f.not_collected, ...f.asset_not_collected.map((x) => `asset.${x}`)];
  const gapsHtml = gapFields.length
    ? `<p class="gap-note">Not collected by this source: ${gapFields.map(esc).join(", ")} — read the related rationale bullets above as "unknown", not "none declared".</p>`
    : "";

  const verdictHtml =
    f.verdict_summary || f.narrative
      ? `<div class="detail-block">
          ${f.verdict_summary ? `<p class="verdict">${esc(f.verdict_summary)}</p>` : ""}
          ${f.narrative ? `<p class="narrative">${esc(f.narrative)}</p>` : ""}
        </div>`
      : "";

  const totNote = f.has_tot
    ? `<p class="tot-note">This finding was contested and routed to Tree-of-Thought — <a href="#" class="jump-to-contested">see its branches in the Contested tab</a>.</p>`
    : "";

  return `
    <div class="finding-detail">
      ${verdictHtml}
      <div class="detail-block">
        <h4>Rationale</h4>
        <ul class="rationale-list">${rationale}</ul>
      </div>
      ${gapsHtml}
      ${totNote}
      <div class="detail-columns">
        <div><h4>Constraints applied</h4>${constraintsApplied}</div>
        <div><h4>Cited evidence</h4>${cited}</div>
      </div>
      <div class="detail-block">
        <h4>Sources</h4>
        ${sources}
      </div>
    </div>
  `;
}

/* ---------------- contested ---------------- */

function renderContested(data) {
  const el = document.getElementById("tab-contested");
  const contested = data.contested;
  const bucketContestedCount = data.findings.filter((f) => f.bucket === "contested").length;

  if (!contested.length) {
    if (bucketContestedCount > 0) {
      const tot = data.pipeline.tot;
      el.innerHTML = `
        <p class="empty-note">
          ${bucketContestedCount} finding(s) landed in the <span class="bucket-pill bucket-contested">${bucketLabel("contested")}</span>
          bucket under the deterministic scoring rules, but this run's <code>tot</code> pipeline stage is
          <strong>${esc(tot.status)}</strong> — ${esc(tot.detail)}. Tree-of-Thought only dispatches on an
          <code>--agents</code> run; see the Findings tab for these findings' deterministic rationale.
        </p>
      `;
    } else {
      el.innerHTML = `<p class="empty-note">No contested findings in this run.</p>`;
    }
    return;
  }

  el.innerHTML = contested.map(contestedCardHtml).join("");
}

function contestedCardHtml(c) {
  if (c.status === "failed") {
    return `
      <div class="card contested-card failed">
        <div class="contested-head">
          <h3>${esc(c.finding_id)} <span class="dim">(${esc(c.cve_id)} on ${esc(c.hostname)})</span></h3>
          <span class="status-pill status-failed">Search failed</span>
        </div>
        <p class="failure-reason">${esc(c.failure_reason)}</p>
      </div>
    `;
  }

  const tieClass = c.near_tie ? "near-tie" : "clear-winner";
  const tieBadge = c.near_tie
    ? `<span class="status-pill status-tie">Near-tie — needs a human tie-break</span>`
    : `<span class="status-pill status-winner">Clear winner: ${strategyLabel(c.winner_strategy)}</span>`;

  const branches = c.branches.map((b) => branchHtml(b, c.near_tie)).join("");

  return `
    <div class="card contested-card ${tieClass}">
      <div class="contested-head">
        <h3>${esc(c.finding_id)} <span class="dim">(${esc(c.cve_id)} on ${esc(c.hostname)})</span></h3>
        ${tieBadge}
      </div>
      <p class="contested-meta">Terminated: ${terminationLabel(c.termination_reason)} · depth ${c.depth_reached}</p>
      <div class="branches">${branches}</div>
    </div>
  `;
}

function branchHtml(b, nearTie) {
  const winnerClass = b.is_winner ? "winner" : nearTie ? "tied" : "";
  const badge = b.is_winner
    ? '<span class="winner-badge">Winner</span>'
    : nearTie
    ? '<span class="tied-badge">Tied</span>'
    : "";

  const axes = AXIS_ORDER.map((a) => {
    const score = b.critic_scores[a];
    const pct = Math.max(0, Math.min(100, (score / 10) * 100));
    return `
      <div class="axis-row">
        <span class="axis-label">${AXIS_LABELS[a]}</span>
        <div class="axis-bar-track"><div class="axis-bar-fill" style="width:${pct}%"></div></div>
        <span class="axis-score">${score.toFixed(1)}</span>
      </div>
    `;
  }).join("");

  return `
    <div class="branch ${winnerClass}">
      <div class="branch-head">
        <span class="branch-strategy">${strategyLabel(b.strategy)}</span>
        ${badge}
        <span class="branch-score">${b.aggregate_score.toFixed(2)}/10</span>
      </div>
      <p class="branch-proposal">${esc(b.proposal)}</p>
      <div class="branch-axes">${axes}</div>
      <p class="branch-justification">${esc(b.critic_scores.justification)}</p>
      ${b.exhausted ? `<p class="exhausted-note">Exhausted: ${esc(b.exhaustion_reason)}</p>` : ""}
    </div>
  `;
}

/* ---------------- scenarios ---------------- */

/* Deterministic and free -- pure filtering/summarizing of data.findings,
 * already fetched. No fetch(), no job substrate, no model call anywhere
 * below. Selection state lives only in this tab/session (a Set of
 * finding_id, persisted to sessionStorage -- see reconcileSelection). */

/* Mirrors scoring.ROLE_BLAST_RADIUS's >=0.85 tier (scoring.py) -- duplicated
 * here rather than shared, the same call this codebase already makes for
 * small code-owned constants that cross a module boundary (e.g. probe.py's
 * own copy of configured.py's CVE-id pattern): cheap to keep in sync, and a
 * static frontend has no Python import to reach for anyway. If scoring.py's
 * table changes, update this list to match. */
const HIGH_BLAST_RADIUS_ROLES = new Set([
  "dc", "exchange", "identity_gateway", "sql", "firewall", "container_orchestrator",
]);

const COVERAGE_ITEM_CAP = 5;
const SCENARIO_PAGE_SIZE = 50;

let scenarioMode = "recommended"; // "recommended" | "selection"
let selectedFindingIds = new Set();
let scenarioSelectionKey = null; // plan-identity key the current selection was loaded/reconciled against
let scenarioReconcileNotice = null; // set by reconcileSelection; shown once, dismissible
let scenarioFilters = {
  buckets: new Set(),
  kev: null, // null = any, true = KEV only, false = non-KEV only
  exposed: null, // null = any, true = internet-exposed only, false = not-exposed only
  role: "",
  highBlastRadius: false,
  onlyUnaddressed: false,
  search: "",
};
let scenarioPage = 1;

function scenarioStorageKey(data) {
  const r = data.run;
  return `rhinosecure:scenario-selection:${r.data_dir}|${r.format}|${r.seed}|${r.agents}`;
}

function loadPersistedSelection(key) {
  try {
    const raw = sessionStorage.getItem(key);
    if (!raw) return new Set();
    const ids = JSON.parse(raw);
    return new Set(Array.isArray(ids) ? ids : []);
  } catch (err) {
    return new Set(); // sessionStorage unavailable (private mode, etc.) -- start clean, never fatal
  }
}

function persistSelection(key) {
  if (!key) return;
  try {
    sessionStorage.setItem(key, JSON.stringify([...selectedFindingIds]));
  } catch (err) {
    // best-effort convenience only -- never block the UI on storage failing
  }
}

/* Runs once per full renderScenarios() pass, never from a results-only
 * update. A DIFFERENT plan identity (data_dir/format/seed/agents changed)
 * starts from THAT plan's own persisted selection rather than inheriting
 * one built against an unrelated fleet; the SAME identity (a live
 * job-triggered refresh, or the same page still open) keeps whatever is
 * already in memory and only drops finding_ids that no longer exist --
 * reported, never silently absorbed. */
function reconcileSelection(data) {
  const key = scenarioStorageKey(data);
  if (key !== scenarioSelectionKey) {
    selectedFindingIds = loadPersistedSelection(key);
    scenarioSelectionKey = key;
  }
  const known = new Set(data.findings.map((f) => f.finding_id));
  const removed = [...selectedFindingIds].filter((id) => !known.has(id));
  if (removed.length) {
    removed.forEach((id) => selectedFindingIds.delete(id));
    scenarioReconcileNotice =
      `${removed.length} previously-selected finding(s) are no longer in this plan and were ` +
      `removed from your selection: ${removed.map(esc).join(", ")}.`;
    persistSelection(key);
  } else {
    scenarioReconcileNotice = null;
  }
}

function recommendedFindingIds(data) {
  return data.findings.filter((f) => f.bucket === "patch_now" || f.bucket === "contested").map((f) => f.finding_id);
}

/* The one predicate the filter bar, the bulk "select/clear shown" actions,
 * and a coverage category's "+N more" link all share -- so "what's
 * visible" and "what a bulk action acts on" can never silently disagree. */
function findingMatchesFilters(f, filters) {
  if (filters.buckets.size && !filters.buckets.has(f.bucket)) return false;
  if (filters.kev === true && !f.is_kev) return false;
  if (filters.kev === false && f.is_kev) return false;
  if (filters.exposed === true && !f.asset.internet_exposed) return false;
  if (filters.exposed === false && f.asset.internet_exposed) return false;
  if (filters.role && f.asset.role !== filters.role) return false;
  if (filters.highBlastRadius && !HIGH_BLAST_RADIUS_ROLES.has(f.asset.role)) return false;
  if (filters.onlyUnaddressed && selectedFindingIds.has(f.finding_id)) return false;
  if (filters.search) {
    const q = filters.search.toLowerCase();
    const hay = `${f.hostname} ${f.cve_id} ${f.finding_id}`.toLowerCase();
    if (!hay.includes(q)) return false;
  }
  return true;
}

function filteredScenarioFindings(data) {
  return data.findings.filter((f) => findingMatchesFilters(f, scenarioFilters));
}

/* "What this selection leaves exposed" -- most severe first, each with
 * real identities (not just a count) up to COVERAGE_ITEM_CAP, plus a
 * bucket-by-bucket addressed/exposed breakdown. `filter` on each category
 * is the partial scenarioFilters a "+N more" click applies -- see
 * wireCoverageLinks. deferred_capacity is deliberately NOT one of these
 * categories (a separate callout below): it means "lost a rank-position
 * race under a capacity limit", not "the plan has nothing to say about
 * this," and folding it into "exposed" would misrepresent that. */
function computeCoverage(findings, selectedIds) {
  const exposed = findings.filter((f) => !selectedIds.has(f.finding_id));

  const categories = [
    {
      key: "patch_now",
      label: "unaddressed patch_now finding(s)",
      items: exposed.filter((f) => f.bucket === "patch_now"),
      filter: { buckets: new Set(["patch_now"]) },
    },
    {
      key: "contested",
      label: "unaddressed contested finding(s)",
      items: exposed.filter((f) => f.bucket === "contested"),
      filter: { buckets: new Set(["contested"]) },
    },
    {
      key: "kev_exposed",
      label: "unaddressed KEV finding(s) that are internet-exposed",
      items: exposed.filter((f) => f.is_kev && f.asset.internet_exposed),
      filter: { kev: true, exposed: true },
    },
    {
      key: "kev_only",
      label: "unaddressed KEV finding(s) (not internet-exposed)",
      items: exposed.filter((f) => f.is_kev && !f.asset.internet_exposed),
      filter: { kev: true, exposed: false },
    },
    {
      key: "high_blast_radius",
      label: "unaddressed finding(s) on a high-blast-radius asset (domain controller, mail/identity, database, or firewall/cluster core)",
      items: exposed.filter((f) => HIGH_BLAST_RADIUS_ROLES.has(f.asset.role)),
      filter: { highBlastRadius: true },
    },
  ];

  const bucketBreakdown = BUCKET_ORDER.map((b) => ({
    bucket: b,
    addressed: findings.filter((f) => f.bucket === b && selectedIds.has(f.finding_id)).length,
    exposed: findings.filter((f) => f.bucket === b && !selectedIds.has(f.finding_id)).length,
  }));

  return {
    total: findings.length,
    addressedCount: findings.length - exposed.length,
    exposedCount: exposed.length,
    categories: categories.filter((c) => c.items.length > 0),
    allClear: categories.every((c) => c.items.length === 0),
    bucketBreakdown,
    deferredCapacityCount: findings.filter((f) => f.bucket === "deferred_capacity").length,
  };
}

function coverageCategoryHtml(cat) {
  const shown = cat.items.slice(0, COVERAGE_ITEM_CAP);
  const extra = cat.items.length - shown.length;
  const itemsText = shown.map((f) => `${esc(f.hostname)}/${esc(f.cve_id)} (${f.risk_score.toFixed(1)})`).join(", ");
  const moreHtml =
    extra > 0
      ? ` <button type="button" class="coverage-more-link" data-category="${esc(cat.key)}">+${extra} more</button>`
      : "";
  return `<li class="coverage-item-row"><strong>${cat.items.length}</strong> ${esc(cat.label)} — ${itemsText}${moreHtml}</li>`;
}

function coverageSummaryHtml(coverage) {
  const capacityNote = coverage.deferredCapacityCount
    ? `<p class="coverage-capacity-note">${coverage.deferredCapacityCount} finding(s) were bumped by a fleet-wide capacity limit this cycle and are not scheduled — see the Constraints tab.</p>`
    : "";
  const body = coverage.allClear
    ? `<p class="coverage-all-clear">No KEV, contested, or high-blast-radius-asset findings left exposed.</p>`
    : `<ul class="coverage-list">${coverage.categories.map(coverageCategoryHtml).join("")}</ul>`;
  const bucketRows = coverage.bucketBreakdown
    .map(
      (row) => `
      <tr>
        <td><span class="bucket-pill bucket-${row.bucket}">${bucketLabel(row.bucket)}</span></td>
        <td class="num">${row.addressed}</td>
        <td class="num">${row.exposed}</td>
      </tr>`
    )
    .join("");

  return `
    <div class="card coverage-card">
      <h3>Coverage</h3>
      <p class="coverage-headline">
        <strong>${coverage.addressedCount}</strong> of ${coverage.total} finding(s) selected —
        leaves <strong>${coverage.exposedCount}</strong> unaddressed
      </p>
      ${capacityNote}
      ${body}
      <table class="bucket-breakdown-table">
        <thead><tr><th>Bucket</th><th>Addressed</th><th>Exposed</th></tr></thead>
        <tbody>${bucketRows}</tbody>
      </table>
    </div>
  `;
}

/* Clicking a coverage category's "+N more" jumps into Selection mode
 * filtered to exactly that category (plus onlyUnaddressed, since every
 * coverage category is about what's NOT yet selected) -- the coverage
 * summary and the filter bar share the same predicate vocabulary
 * (findingMatchesFilters), so "what this line describes" and "what you see
 * after clicking it" can never drift apart. */
function wireCoverageLinks(container, categories) {
  const byKey = Object.fromEntries(categories.map((c) => [c.key, c.filter]));
  container.querySelectorAll(".coverage-more-link").forEach((btn) => {
    btn.addEventListener("click", () => {
      const partial = byKey[btn.dataset.category];
      if (!partial) return;
      scenarioFilters = {
        buckets: new Set(), kev: null, exposed: null, role: "",
        highBlastRadius: false, onlyUnaddressed: true, search: "",
        ...partial,
      };
      scenarioMode = "selection";
      scenarioPage = 1;
      renderScenarios();
    });
  });
}

function scenarioTableHtml(rows, opts) {
  const withCheckboxes = Boolean(opts && opts.withCheckboxes);
  const checkboxHeader = withCheckboxes ? "<th></th>" : "";
  const trs = rows
    .map((f) => {
      const checkboxCell = withCheckboxes
        ? `<td><input type="checkbox" class="scenario-row-checkbox" data-finding-id="${esc(f.finding_id)}" ${
            selectedFindingIds.has(f.finding_id) ? "checked" : ""
          }></td>`
        : "";
      return `
        <tr class="scenario-row">
          ${checkboxCell}
          <td><code>${esc(f.finding_id)}</code></td>
          <td>${esc(f.cve_id)}</td>
          <td>${esc(f.hostname)}</td>
          <td><span class="bucket-pill bucket-${esc(f.bucket)}">${bucketLabel(f.bucket)}</span></td>
          <td class="num">${f.risk_score.toFixed(1)}</td>
          <td>${f.is_kev ? '<span class="flag-yes">KEV</span>' : '<span class="dim">—</span>'}</td>
          <td>${f.asset.internet_exposed ? '<span class="flag-yes">Exposed</span>' : '<span class="dim">—</span>'}</td>
          <td>${esc(f.asset.role)}</td>
          <td><button type="button" class="view-finding-link" data-finding-id="${esc(f.finding_id)}">View</button></td>
        </tr>
      `;
    })
    .join("");

  return `
    <table class="findings-table scenario-table">
      <thead>
        <tr>${checkboxHeader}<th>Finding</th><th>CVE</th><th>Host</th><th>Bucket</th><th>Risk</th><th>KEV</th><th>Exposed</th><th>Role</th><th></th></tr>
      </thead>
      <tbody>${trs}</tbody>
    </table>
  `;
}

function wireScenarioRowLinks(container) {
  container.querySelectorAll(".view-finding-link").forEach((btn) => {
    btn.addEventListener("click", () => jumpToFinding(btn.dataset.findingId));
  });
}

/* ---- Recommended mode: fixed, read-only ---- */

function recommendedModeHtml(data) {
  const recommended = [...data.findings]
    .filter((f) => f.bucket === "patch_now" || f.bucket === "contested")
    .sort((a, b) => b.risk_score - a.risk_score);
  const recommendedIds = new Set(recommended.map((f) => f.finding_id));
  const coverage = computeCoverage(data.findings, recommendedIds);

  const tableHtml = recommended.length
    ? scenarioTableHtml(recommended, { withCheckboxes: false })
    : `<p class="empty-note">Nothing lands in patch_now or contested in this plan right now.</p>`;

  return `
    <div class="card">
      <h3>What the plan says to patch now</h3>
      <p class="hint">
        Every <span class="bucket-pill bucket-patch_now">${bucketLabel("patch_now")}</span> finding, plus every
        <span class="bucket-pill bucket-contested">${bucketLabel("contested")}</span> finding -- the deterministic
        scorer could not honestly assign one of the four real buckets to these, so they need human or
        Tree-of-Thought judgment rather than being silently treated as fine.
      </p>
      ${tableHtml}
      ${
        recommended.length
          ? `<button type="button" class="secondary-btn" id="start-from-recommended-btn">Start a custom selection from this set (${recommended.length})</button>`
          : ""
      }
    </div>
    ${coverageSummaryHtml(coverage)}
  `;
}

function wireRecommendedModeEvents(data) {
  const tab = document.getElementById("tab-scenarios");
  const recommendedIds = recommendedFindingIds(data);

  const startBtn = document.getElementById("start-from-recommended-btn");
  if (startBtn) {
    startBtn.addEventListener("click", () => {
      selectedFindingIds = new Set(recommendedIds);
      persistSelection(scenarioSelectionKey);
      scenarioMode = "selection";
      scenarioPage = 1;
      renderScenarios();
    });
  }

  wireCoverageLinks(tab, computeCoverage(data.findings, new Set(recommendedIds)).categories);
  wireScenarioRowLinks(tab);
}

/* ---- Selection mode: bulk filter + build a custom scenario ---- */

function kevFilterLabel(state) {
  if (state === true) return "KEV: yes";
  if (state === false) return "KEV: no";
  return "KEV: any";
}
function exposedFilterLabel(state) {
  if (state === true) return "Exposed: yes";
  if (state === false) return "Exposed: no";
  return "Exposed: any";
}
function cycleTriState(state) {
  if (state === null) return true;
  if (state === true) return false;
  return null;
}
function distinctRoles(findings) {
  return [...new Set(findings.map((f) => f.asset.role))].sort();
}

function selectionModeHtml(data) {
  const roles = distinctRoles(data.findings);
  const bucketChips = BUCKET_ORDER.map(
    (b) => `
      <button type="button" class="chip bucket-chip bucket-${b} ${scenarioFilters.buckets.has(b) ? "active" : ""}" data-bucket="${b}">${bucketLabel(b)}</button>`
  ).join("");
  const roleOptions = [
    `<option value="">All roles</option>`,
    `<option value="__high__" ${scenarioFilters.highBlastRadius ? "selected" : ""}>High blast radius (dc, exchange, sql, firewall...)</option>`,
    ...roles.map(
      (r) =>
        `<option value="${esc(r)}" ${!scenarioFilters.highBlastRadius && scenarioFilters.role === r ? "selected" : ""}>${esc(r)}</option>`
    ),
  ].join("");

  return `
    <div class="card scenario-filter-card">
      <div class="filter-row">
        <div class="filter-group">${bucketChips}</div>
        <button type="button" class="chip tri-chip" id="kev-filter-btn">${kevFilterLabel(scenarioFilters.kev)}</button>
        <button type="button" class="chip tri-chip" id="exposed-filter-btn">${exposedFilterLabel(scenarioFilters.exposed)}</button>
        <select id="role-filter-select">${roleOptions}</select>
        <input type="search" id="scenario-search-input" placeholder="Search host, CVE, finding ID" value="${esc(scenarioFilters.search)}">
        <label class="checkbox-label">
          <input type="checkbox" id="only-unaddressed-checkbox" ${scenarioFilters.onlyUnaddressed ? "checked" : ""}> Only unaddressed
        </label>
      </div>
    </div>
    <div id="scenario-results"></div>
  `;
}

function scenarioResultsHtml(data) {
  const filtered = filteredScenarioFindings(data);
  const shown = filtered.slice(0, scenarioPage * SCENARIO_PAGE_SIZE);
  const hasMore = shown.length < filtered.length;

  const toolbarHtml = `
    <div class="selection-toolbar">
      <span class="selection-count">
        ${filtered.length} of ${data.findings.length} finding(s) match this filter ·
        <strong>${selectedFindingIds.size} selected</strong>
      </span>
      <div class="toolbar-actions">
        <button type="button" id="select-filtered-btn" ${filtered.length ? "" : "disabled"}>Select all ${filtered.length} shown</button>
        <button type="button" id="clear-filtered-btn" ${filtered.length ? "" : "disabled"}>Clear shown from selection</button>
        <button type="button" id="clear-selection-btn" ${selectedFindingIds.size ? "" : "disabled"}>Clear entire selection</button>
        <button type="button" id="start-from-recommended-btn">Start from recommended</button>
      </div>
    </div>
  `;

  const tableHtml = shown.length
    ? scenarioTableHtml(shown, { withCheckboxes: true })
    : `<p class="empty-note">No findings match this filter.</p>`;

  const loadMoreHtml = hasMore
    ? `<button type="button" id="scenario-load-more-btn" class="secondary-btn">Load more (showing ${shown.length} of ${filtered.length})</button>`
    : "";

  const coverage = computeCoverage(data.findings, selectedFindingIds);

  return `${toolbarHtml}${tableHtml}${loadMoreHtml}${coverageSummaryHtml(coverage)}`;
}

/* Rebuilds only #scenario-results -- never the filter bar itself, so
 * typing in the search box never loses focus/cursor position (the classic
 * innerHTML-replace-while-typing bug). Every mutation that doesn't touch
 * the filter bar's own controls (a checkbox click, a bulk action, a
 * search keystroke) goes through this; anything that changes the filter
 * bar's own rendered state (a chip, the tri-state buttons, the role
 * select) goes through the fuller wireSelectionModeEvents/renderScenarios
 * instead, which is safe since those are discrete clicks, not typing. */
function updateScenarioResults(data) {
  const container = document.getElementById("scenario-results");
  if (!container) return;
  container.innerHTML = scenarioResultsHtml(data);
  wireScenarioResultsEvents(data);
}

function wireScenarioResultsEvents(data) {
  const container = document.getElementById("scenario-results");
  if (!container) return;

  container.querySelectorAll(".scenario-row-checkbox").forEach((cb) => {
    cb.addEventListener("change", () => {
      if (cb.checked) selectedFindingIds.add(cb.dataset.findingId);
      else selectedFindingIds.delete(cb.dataset.findingId);
      persistSelection(scenarioSelectionKey);
      updateScenarioResults(data);
    });
  });

  const selectFilteredBtn = document.getElementById("select-filtered-btn");
  if (selectFilteredBtn) {
    selectFilteredBtn.addEventListener("click", () => {
      filteredScenarioFindings(data).forEach((f) => selectedFindingIds.add(f.finding_id));
      persistSelection(scenarioSelectionKey);
      updateScenarioResults(data);
    });
  }
  const clearFilteredBtn = document.getElementById("clear-filtered-btn");
  if (clearFilteredBtn) {
    clearFilteredBtn.addEventListener("click", () => {
      filteredScenarioFindings(data).forEach((f) => selectedFindingIds.delete(f.finding_id));
      persistSelection(scenarioSelectionKey);
      updateScenarioResults(data);
    });
  }
  const clearSelectionBtn = document.getElementById("clear-selection-btn");
  if (clearSelectionBtn) {
    clearSelectionBtn.addEventListener("click", () => {
      selectedFindingIds.clear();
      persistSelection(scenarioSelectionKey);
      updateScenarioResults(data);
    });
  }
  const startFromRecommendedBtn = document.getElementById("start-from-recommended-btn");
  if (startFromRecommendedBtn) {
    startFromRecommendedBtn.addEventListener("click", () => {
      selectedFindingIds = new Set(recommendedFindingIds(data));
      persistSelection(scenarioSelectionKey);
      updateScenarioResults(data);
    });
  }
  const loadMoreBtn = document.getElementById("scenario-load-more-btn");
  if (loadMoreBtn) {
    loadMoreBtn.addEventListener("click", () => {
      scenarioPage += 1;
      updateScenarioResults(data);
    });
  }

  wireCoverageLinks(container, computeCoverage(data.findings, selectedFindingIds).categories);
  wireScenarioRowLinks(container);
}

function wireSelectionModeEvents(data) {
  const tab = document.getElementById("tab-scenarios");

  tab.querySelectorAll(".bucket-chip").forEach((btn) => {
    btn.addEventListener("click", () => {
      const b = btn.dataset.bucket;
      if (scenarioFilters.buckets.has(b)) scenarioFilters.buckets.delete(b);
      else scenarioFilters.buckets.add(b);
      scenarioPage = 1;
      renderScenarios();
    });
  });
  const kevBtn = document.getElementById("kev-filter-btn");
  if (kevBtn) {
    kevBtn.addEventListener("click", () => {
      scenarioFilters.kev = cycleTriState(scenarioFilters.kev);
      scenarioPage = 1;
      renderScenarios();
    });
  }
  const exposedBtn = document.getElementById("exposed-filter-btn");
  if (exposedBtn) {
    exposedBtn.addEventListener("click", () => {
      scenarioFilters.exposed = cycleTriState(scenarioFilters.exposed);
      scenarioPage = 1;
      renderScenarios();
    });
  }
  const roleSelect = document.getElementById("role-filter-select");
  if (roleSelect) {
    roleSelect.addEventListener("change", () => {
      const v = roleSelect.value;
      scenarioFilters.highBlastRadius = v === "__high__";
      scenarioFilters.role = v === "__high__" ? "" : v;
      scenarioPage = 1;
      renderScenarios();
    });
  }
  const onlyUnaddressed = document.getElementById("only-unaddressed-checkbox");
  if (onlyUnaddressed) {
    onlyUnaddressed.addEventListener("change", () => {
      scenarioFilters.onlyUnaddressed = onlyUnaddressed.checked;
      scenarioPage = 1;
      renderScenarios();
    });
  }
  const searchInput = document.getElementById("scenario-search-input");
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      scenarioFilters.search = searchInput.value;
      scenarioPage = 1;
      updateScenarioResults(data); // results only -- see updateScenarioResults' own note
    });
  }

  updateScenarioResults(data);
}

/* ---- entry point ---- */

function renderScenarios() {
  const data = lastExportData;
  const el = document.getElementById("tab-scenarios");
  if (!data || !el) return;

  reconcileSelection(data);
  scenarioPage = 1;

  if (!data.findings.length) {
    el.innerHTML = `<p class="empty-note">No findings in this export.</p>`;
    return;
  }

  const noticeHtml = scenarioReconcileNotice
    ? `<div class="scenario-notice">${esc(scenarioReconcileNotice)} <button type="button" class="dismiss-notice-btn" id="dismiss-reconcile-notice" aria-label="Dismiss">&times;</button></div>`
    : "";
  const modeToggleHtml = `
    <div class="scenario-mode-toggle">
      <button type="button" class="mode-btn ${scenarioMode === "recommended" ? "active" : ""}" data-mode="recommended">Recommended</button>
      <button type="button" class="mode-btn ${scenarioMode === "selection" ? "active" : ""}" data-mode="selection">Selection</button>
    </div>
  `;

  el.innerHTML = `${noticeHtml}${modeToggleHtml}<div id="scenario-body"></div>`;

  const dismissBtn = document.getElementById("dismiss-reconcile-notice");
  if (dismissBtn) {
    dismissBtn.addEventListener("click", () => {
      scenarioReconcileNotice = null;
      const notice = el.querySelector(".scenario-notice");
      if (notice) notice.remove();
    });
  }
  el.querySelectorAll(".mode-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      scenarioMode = btn.dataset.mode;
      scenarioPage = 1;
      renderScenarios();
    });
  });

  const body = document.getElementById("scenario-body");
  if (scenarioMode === "recommended") {
    body.innerHTML = recommendedModeHtml(data);
    wireRecommendedModeEvents(data);
  } else {
    body.innerHTML = selectionModeHtml(data);
    wireSelectionModeEvents(data);
  }
}

/* ---------------- constraints ---------------- */

function renderConstraints(data) {
  const el = document.getElementById("tab-constraints");
  const { asset_scoped: assetScoped, capacity } = data.constraints;

  const submitHtml = jobsEnabled ? constraintSubmitFormHtml() : "";

  const assetHtml = assetScoped.length
    ? assetScoped.map(assetConstraintHtml).join("")
    : `<p class="empty-note">No asset-scoped constraints on file.</p>`;

  const capacityHtml = capacity.length
    ? capacity.map(capacityConstraintHtml).join("")
    : `<p class="empty-note">No capacity constraints on file.</p>`;

  el.innerHTML = `
    ${submitHtml}
    <div class="constraints-section">
      <h3>Asset-scoped constraints</h3>
      ${assetHtml}
    </div>
    <div class="constraints-section">
      <h3>Capacity constraints</h3>
      ${capacityHtml}
    </div>
  `;

  if (jobsEnabled) {
    document.getElementById("constraint-submit-form").addEventListener("submit", (e) => {
      e.preventDefault();
      const input = document.getElementById("constraint-text-input");
      const text = input.value.trim();
      if (text) submitConstraint(text, input);
    });
  }
}

function constraintSubmitFormHtml() {
  return `
    <div class="card constraint-submit-card">
      <h3>Submit a constraint</h3>
      <p class="hint">
        Plain English -- e.g. &ldquo;the finance workstation can only be rebooted on Sundays
        between 02:00 and 06:00&rdquo;, or a fleet-wide &ldquo;only five patches fit this
        window&rdquo;. Runs as a background job -- this page keeps working while it does.
      </p>
      <form id="constraint-submit-form">
        <textarea id="constraint-text-input" rows="2" placeholder="Describe the operational constraint..."></textarea>
        <button type="submit" id="constraint-submit-btn">Submit</button>
      </form>
    </div>
  `;
}

/* ---------------- job submission + polling ---------------- */

let jobsEnabled = false;
let jobPollTimer = null;

function setJobStatus(kind, html) {
  const el = document.getElementById("job-status");
  el.className = `job-status ${kind}`;
  el.innerHTML = html;
  el.hidden = false;
}

async function submitConstraint(text, input) {
  clearTimeout(jobPollTimer);
  const btn = document.getElementById("constraint-submit-btn");
  if (btn) btn.disabled = true;
  setJobStatus("progress", `<span class="spinner"></span> Submitting…`);

  let jobId;
  try {
    const res = await fetch("/api/jobs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind: "constraint_submit", input: { text } }),
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.detail || `HTTP ${res.status}`);
    jobId = body.job_id;
  } catch (err) {
    setJobStatus("error", `Could not submit: ${esc(err.message)}`);
    if (btn) btn.disabled = false;
    return;
  }

  pollJob(jobId, input);
}

function pollJob(jobId, input) {
  const tick = async () => {
    let body;
    try {
      const res = await fetch(`/api/jobs/${jobId}`);
      body = await res.json();
    } catch (err) {
      jobPollTimer = setTimeout(tick, 1500); // transient network hiccup -- keep polling the same job
      return;
    }

    if (body.status === "pending" || body.status === "running") {
      setJobStatus("progress", `<span class="spinner"></span> ${jobStageLabel(body.stage)}…`);
      jobPollTimer = setTimeout(tick, 1200);
      return;
    }

    const btn = document.getElementById("constraint-submit-btn");
    if (btn) btn.disabled = false;

    if (body.status === "succeeded") {
      handleJobSucceeded(body, input);
    } else {
      handleJobFailed(body);
    }
  };
  tick();
}

function handleJobSucceeded(job, input) {
  const r = job.result || {};
  if (!r.persisted) {
    const rationale =
      (r.interpretation && r.interpretation.rationale) ||
      "it didn't resolve to one asset or a recognizable capacity limit.";
    setJobStatus("info", `Nothing to apply — ${esc(rationale)}`);
    return;
  }

  if (input) input.value = "";
  const deltas = r.deltas || [];
  const changed = deltas.filter((d) => d.changed);
  const summary = changed.length
    ? changed.map(deltaSummary).join("; ")
    : `${deltas.length} finding(s) re-evaluated — no bucket or risk score changed`;

  let html = `Applied — ${summary}.`;
  let kind = "success";
  if (job.export_warning) {
    kind = "warning";
    html += `<br>${esc(job.export_warning)}`;
  }
  setJobStatus(kind, html);

  if (job.export_written) refreshExportAfterJob();
}

function handleJobFailed(job) {
  const e = job.error || {};
  let message = `${esc(e.type || "Error")} while ${jobStageLabel(e.stage)}: ${esc(e.message || "unknown error")}`;
  if (e.constraint_id != null) {
    message +=
      ` Constraint #${esc(e.constraint_id)} for asset ${esc(e.asset_id)} was recorded and is ` +
      `still active — it will apply the next time the plan is refreshed.`;
  }
  setJobStatus("error", message);
}

async function refreshExportAfterJob() {
  try {
    const res = await fetch("/api/export");
    if (!res.ok) return;
    renderAll(await res.json());
  } catch (err) {
    // the constraint DID apply -- a transient refresh failure here isn't
    // worth turning into a hard error on top of a successful submission.
  }
}

function assetConstraintHtml(c) {
  const deltas = c.deltas.length
    ? `<table class="deltas-table">
        <thead><tr><th>Finding</th><th>Before</th><th>After</th></tr></thead>
        <tbody>${c.deltas
          .map(
            (d) => `
          <tr class="${d.changed ? "changed" : ""}">
            <td><code>${esc(d.finding_id)}</code> <span class="dim">${esc(d.cve_id)} / ${esc(d.hostname)}</span></td>
            <td><span class="bucket-pill bucket-${esc(d.before_bucket)}">${bucketLabel(d.before_bucket)}</span> ${d.before_risk_score.toFixed(1)}</td>
            <td><span class="bucket-pill bucket-${esc(d.after_bucket)}">${bucketLabel(d.after_bucket)}</span> ${d.after_risk_score.toFixed(1)}${d.changed ? ' <span class="changed-flag">changed</span>' : ""}</td>
          </tr>`
          )
          .join("")}</tbody>
      </table>`
    : `<p class="empty-note">No findings affected in this run.</p>`;

  return `
    <div class="card constraint-card ${c.active ? "" : "inactive"}">
      <div class="constraint-head">
        <h4>#${esc(c.constraint_id)} on <code>${esc(c.asset_id)}</code></h4>
        <span class="status-pill ${c.active ? "status-active" : "status-inactive"}">${c.active ? "Active" : "Retracted"}</span>
      </div>
      <p class="constraint-text">&ldquo;${esc(c.constraint_text)}&rdquo;</p>
      <p class="constraint-meta">${esc(c.effect_kind)} = ${esc(c.effect_value)} · filed ${formatTime(c.created_at)}</p>
      ${c.note ? `<p class="constraint-note">${esc(c.note)}</p>` : ""}
      ${deltas}
    </div>
  `;
}

function capacityConstraintHtml(c) {
  const deltas = c.deltas.length
    ? `<table class="deltas-table">
        <thead><tr><th>Rank</th><th>Finding</th><th>Risk</th><th>Result</th></tr></thead>
        <tbody>${c.deltas
          .map(
            (d) => `
          <tr class="${d.fits ? "" : "deferred"}">
            <td>#${d.rank}/${d.pool_size}</td>
            <td><code>${esc(d.finding_id)}</code> <span class="dim">${esc(d.cve_id)} / ${esc(d.hostname)}</span></td>
            <td>${d.risk_score.toFixed(1)}</td>
            <td><span class="bucket-pill bucket-${d.fits ? "next_window" : "deferred_capacity"}">${d.fits ? "Fits (next_window)" : "Deferred (capacity)"}</span></td>
          </tr>`
          )
          .join("")}</tbody>
      </table>`
    : `<p class="empty-note">No next_window findings were competing for capacity.</p>`;

  return `
    <div class="card constraint-card ${c.stale ? "stale" : ""}">
      <div class="constraint-head">
        <h4>#${esc(c.capacity_constraint_id)} — limit ${esc(c.patch_limit)}</h4>
        ${c.stale ? '<span class="status-pill status-stale">Stale — from a different run</span>' : '<span class="status-pill status-active">Current run</span>'}
      </div>
      <p class="constraint-text">&ldquo;${esc(c.raw_text)}&rdquo;</p>
      <p class="constraint-meta">pool ${c.pool_size} · deferred ${c.deferred_count} · filed ${formatTime(c.created_at)}</p>
      <p class="constraint-meta dim">source run: ${esc(baseName(c.source_run.data_dir))} (${esc(c.source_run.ingest_format)}, seed ${esc(c.source_run.seed)})</p>
      ${deltas}
    </div>
  `;
}

/* ---------------- chat ---------------- */

/* Chat is the one place this file deliberately deviates from "never cache
 * the export payload" (see the top-of-file note) -- a citation chip needs
 * to jump to and open the exact finding row it names, which means knowing
 * that finding's index in the currently-rendered table. `lastExportData`
 * exists ONLY for that cross-link; nothing renders from it directly. */
let lastExportData = null;
let chatEnabled = false;
let chatHistory = []; // [{role: "user"|"assistant", content: string}, ...]
const MAX_CLIENT_CHAT_HISTORY = 20;

function citationChipHtml(c) {
  return `
    <button type="button" class="citation-chip" data-finding-id="${esc(c.finding_id)}"
            title="${esc(c.cve_id)} on ${esc(c.hostname)} — jump to this finding">
      <code>${esc(c.finding_id)}</code>
      <span class="bucket-pill bucket-${esc(c.bucket)}">${bucketLabel(c.bucket)}</span>
      <span class="citation-score">${c.risk_score.toFixed(1)}</span>
    </button>
  `;
}

function appendChatMessage(role, content, opts) {
  opts = opts || {};
  const citations = opts.citations || [];
  const insufficient = Boolean(opts.insufficientData);

  const container = document.getElementById("chat-messages");
  const bubble = document.createElement("div");
  bubble.className = `chat-msg chat-msg-${role}${insufficient ? " insufficient" : ""}`;

  const insufficientHtml = insufficient
    ? `<p class="chat-insufficient">Not answerable from this plan${opts.insufficientReason ? `: ${esc(opts.insufficientReason)}` : "."}</p>`
    : "";
  const chipsHtml = citations.length
    ? `<div class="citation-chips">${citations.map(citationChipHtml).join("")}</div>`
    : "";

  bubble.innerHTML = `
    <p class="chat-msg-content">${esc(content).replace(/\n/g, "<br>")}</p>
    ${insufficientHtml}
    ${chipsHtml}
  `;
  container.appendChild(bubble);
  container.scrollTop = container.scrollHeight;

  bubble.querySelectorAll(".citation-chip").forEach((btn) => {
    btn.addEventListener("click", () => jumpToFinding(btn.dataset.findingId));
  });
  return bubble;
}

function setChatTyping(on) {
  const existing = document.getElementById("chat-typing");
  if (existing) existing.remove();
  if (!on) return;
  const container = document.getElementById("chat-messages");
  const el = document.createElement("div");
  el.id = "chat-typing";
  el.className = "chat-typing";
  el.innerHTML = `<span class="spinner"></span> Thinking…`;
  container.appendChild(el);
  container.scrollTop = container.scrollHeight;
}

function jumpToFinding(findingId) {
  if (!lastExportData) return;
  const idx = lastExportData.findings.findIndex((f) => f.finding_id === findingId);
  if (idx === -1) return;
  switchTab("findings");
  requestAnimationFrame(() => {
    const row = document.querySelector(`.finding-row[data-idx="${idx}"]`);
    if (!row) return;
    row.scrollIntoView({ behavior: "smooth", block: "center" });
    if (!row.classList.contains("open")) {
      toggleFindingDetail(row, lastExportData.findings[idx]);
    }
  });
}

async function submitChatMessage(text) {
  const sendBtn = document.getElementById("chat-send-btn");
  const priorHistory = chatHistory.slice(-MAX_CLIENT_CHAT_HISTORY);

  appendChatMessage("user", text);
  chatHistory.push({ role: "user", content: text });
  if (sendBtn) sendBtn.disabled = true;
  setChatTyping(true);

  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: text, history: priorHistory }),
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.detail || `HTTP ${res.status}`);

    appendChatMessage("assistant", body.answer, {
      citations: body.citations,
      insufficientData: body.insufficient_data,
      insufficientReason: body.insufficient_reason,
    });
    chatHistory.push({ role: "assistant", content: body.answer });
  } catch (err) {
    const bubble = appendChatMessage("assistant", `Could not answer: ${err.message}`);
    bubble.classList.add("chat-msg-error");
  } finally {
    setChatTyping(false);
    if (sendBtn) sendBtn.disabled = false;
  }
}

function openChatPanel() {
  document.getElementById("chat-panel").hidden = false;
  document.getElementById("chat-input").focus();
}

function closeChatPanel() {
  document.getElementById("chat-panel").hidden = true;
}

function setupChat() {
  document.getElementById("chat-toggle-btn").hidden = false;
  document.getElementById("chat-toggle-btn").addEventListener("click", () => {
    const panel = document.getElementById("chat-panel");
    if (panel.hidden) openChatPanel();
    else closeChatPanel();
  });
  document.getElementById("chat-close-btn").addEventListener("click", closeChatPanel);
  document.getElementById("chat-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const input = document.getElementById("chat-input");
    const text = input.value.trim();
    if (!text) return;
    input.value = "";
    submitChatMessage(text);
  });
}

/* ---------------- boot ---------------- */

function renderAll(data) {
  lastExportData = data;
  document.title = `RhinoSecure — ${baseName(data.run.data_dir)} (${data.run.agents ? "agents" : "deterministic"})`;
  renderRunMeta(data);
  renderPipeline(data);
  renderOverview(data);
  renderFindings(data);
  renderContested(data);
  renderScenarios();
  renderConstraints(data);
}

async function boot() {
  setupTabs();

  try {
    const health = await fetch("/api/health").then((r) => r.json());
    jobsEnabled = Boolean(health.jobs_enabled);
    chatEnabled = Boolean(health.chat_enabled);
  } catch (err) {
    jobsEnabled = false; // health check itself failing is not fatal to the read-only view below
    chatEnabled = false;
  }

  if (chatEnabled) setupChat();

  try {
    const res = await fetch("/api/export");
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || `HTTP ${res.status}`);
    }
    const data = await res.json();
    renderAll(data);
  } catch (err) {
    showError(`Could not load export data: ${err.message}`);
  }
}

document.addEventListener("DOMContentLoaded", boot);
