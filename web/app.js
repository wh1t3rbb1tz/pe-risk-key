"use strict";

/* Display labels (presentation only; every data value comes from the API). */
const DEAL_LABELS = {
  escalate_full_diligence: "Escalate: full cyber diligence required before signing",
  reprice_or_restructure: "Reprice or restructure",
  proceed_with_conditions: "Proceed with conditions",
  proceed: "Proceed",
};
const CAP_LABELS = {
  "CAP-CRIT": "a critical, potentially exploitable exposure",
  "CAP-INCIDENT": "a publicly disclosed incident within 24 months",
  "CAP-CONTRADICTION": "multiple management statements contradicted by evidence",
  "CAP-SOC2-QUAL": "a qualified SOC 2 opinion",
  "CAP-LOW-COVERAGE": "limited evidence: outside-in signals only",
};
const WINDOW_ORDER = ["days_0_30", "days_31_60", "days_61_100", "post_100"];
const WINDOW_LABELS = {
  days_0_30: "Days 0–30",
  days_31_60: "Days 31–60",
  days_61_100: "Days 61–100",
  post_100: "After day 100",
};
const FUNCTION_NAMES = {
  GV: "Govern",
  ID: "Identify",
  PR: "Protect",
  DE: "Detect",
  RS: "Respond",
  RC: "Recover",
};
const REC_LABELS = {
  closing_condition: "Closing condition",
  specific_indemnity: "Specific indemnity",
  escrow_or_holdback: "Escrow / holdback",
  price_adjustment: "Price adjustment",
  rw_insurance_note: "R&W insurance note",
  cyber_insurance: "Cyber insurance",
  post_close_covenant: "Post-close covenant",
  full_diligence_scope: "Full diligence scope",
};
const METHOD_LABELS = {
  dns_query: "DNS",
  ct_log_query: "CT log",
  single_https_get: "HTTPS",
  offline_lookup: "CISA KEV",
  search_grounding: "Public record",
  document_upload: "SOC 2",
  interview_upload: "Interview",
};
const SOURCE_LABELS = {
  outside_in: "Outside-in",
  document: "Document",
  interview: "Interview",
  crosscheck: "Cross-check",
  public_record: "Public record",
};
const STAGES = [
  "collecting",
  "analyzing_documents",
  "transcribing",
  "cross_checking",
  "scoring",
  "writing_narrative",
  "complete",
];
const STAGE_LABELS = {
  collecting: "Collecting",
  analyzing_documents: "Analyzing documents",
  transcribing: "Transcribing",
  cross_checking: "Cross-checking",
  scoring: "Scoring",
  writing_narrative: "Writing narrative",
  complete: "Complete",
};
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const VERDICT_RANK = { contradicted: 0, unsupported: 1, supported: 2 };
const CONTROL_RE = /\b((?:CC|A|C|PI|P)\d+\.\d+)\b/;
const CITE_RE = /\[((?:F|C)-\d{3})\]/g;

const $ = (id) => document.getElementById(id);
const REDUCED_MOTION = window.matchMedia(
  "(prefers-reduced-motion: reduce)"
).matches;
const PRESENT = new URLSearchParams(window.location.search).has("present");

/* Per-run state, reset by resetRun(). */
let runId = null;
let eventSource = null;
let streamDone = false;
let isReplay = false;
let nextChipAt = 0;
let chipTimers = [];
let evidence = null;
let interviewDurEl = null;
let seenSeq = new Set();
let verdictQueue = [];
let verdictTimer = null;
let shownVerdicts = new Set();
let memoTimer = null;
let memoStart = 0;
let totalTokens = 0;
let runCost = null;
let evidenceById = {};
let findingById = {};
let groupEls = {};
let groupCounts = {};
let laneEls = {};
let crossCounts = { contradicted: 0, unsupported: 0, supported: 0 };
let adjustments = [];
let previewDigest = null;
let costByDigest = {};
let statusByDigest = {};
let narrativeValidByDigest = {};
let runNarrativeValid = null;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function fmtMoney(value) {
  const num = Number(value) || 0;
  if (num >= 1000) {
    const k = Math.round(num / 100) / 10;
    return "$" + String(k).replace(/\.0$/, "") + "K";
  }
  return "$" + num;
}

function fmtRange(low, high) {
  if (low === high) return fmtMoney(low);
  return fmtMoney(low) + "–" + fmtMoney(high);
}

function fmtCost(value) {
  if (value === null || value === undefined) return "—";
  return value < 0.01 ? "$" + Number(value).toFixed(4) : "$" + Number(value).toFixed(2);
}

function fmtDuration(ms) {
  if (ms === null || ms === undefined) return "—";
  return ms < 1000 ? Math.round(ms) + "ms" : (ms / 1000).toFixed(1) + "s";
}

function fmtTokens(n) {
  return n >= 1000 ? (n / 1000).toFixed(1) + "k" : String(n);
}

function fmtTokensDict(tokens) {
  if (!tokens) return "";
  const p = tokens.prompt_tokens || 0;
  const c = tokens.completion_tokens || 0;
  return fmtTokens(p + c) + " tok";
}

function addTokens(tokens) {
  if (!tokens) return;
  totalTokens +=
    (tokens.prompt_tokens || 0) + (tokens.completion_tokens || 0);
  updateTicker();
}

function addCost(costUsd) {
  if (costUsd === null || costUsd === undefined) return;
  runCost = (runCost || 0) + costUsd;
  updateTicker();
}

function updateTicker() {
  $("cost-ticker").textContent =
    fmtCost(runCost === null ? 0 : runCost) +
    " · " +
    fmtTokens(totalTokens) +
    " tokens";
  const decCost = $("dec-cost");
  if (decCost) decCost.textContent = fmtCost(runCost);
}

function apiError(status, detail) {
  const error = new Error(
    "Could not reach the API (status " + status + ")"
  );
  error.isApiError = true;
  error.status = status;
  error.detail = detail;
  return error;
}

async function api(path, options) {
  let response;
  try {
    response = await fetch(path, options);
  } catch (err) {
    throw apiError("unreachable", String((err && err.message) || err));
  }
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.detail || detail;
    } catch (_) {
      /* keep status text */
    }
    throw apiError(response.status, path + ": " + detail);
  }
  return response.json();
}

function displayError(err) {
  console.error((err && err.stack) || err);
  showRailError(
    "Display error: " + String((err && err.message) || err)
  );
}

/* ---- run list + picker ---- */

function fmtDateTime(iso) {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  const pad = (n) => String(n).padStart(2, "0");
  return (
    date.getFullYear() +
    "-" +
    pad(date.getMonth() + 1) +
    "-" +
    pad(date.getDate()) +
    " " +
    pad(date.getHours()) +
    ":" +
    pad(date.getMinutes())
  );
}

function fmtInputs(entry) {
  let label = "outside-in";
  if (entry.has_soc2) label += " +SOC 2";
  if (entry.has_interview) label += " +interview";
  return label;
}

function runLabel(entry) {
  const target = entry.target || {};
  const company = target.name || target.domain || entry.digest_id;
  return (
    company +
    " · " +
    (entry.rating || entry.status) +
    " · " +
    fmtDateTime(entry.generated_at) +
    " · " +
    fmtInputs(entry) +
    " · " +
    (entry.cost === null || entry.cost === undefined
      ? "—"
      : fmtCost(entry.cost))
  );
}

async function loadRuns(autoselect) {
  const body = await api("/api/digests");
  costByDigest = {};
  statusByDigest = {};
  narrativeValidByDigest = {};
  const picker = $("run-picker");
  picker
    .querySelectorAll('option:not([value=""])')
    .forEach((o) => o.remove());
  const older = $("older-list");
  older.replaceChildren();
  let mainCount = 0;
  for (const entry of body.digests || []) {
    costByDigest[entry.digest_id] = entry.cost;
    statusByDigest[entry.digest_id] = entry.status;
    narrativeValidByDigest[entry.digest_id] = entry.narrative_valid;
    if (entry.complete && entry.authoritative) {
      mainCount += 1;
      const option = el("option");
      option.value = entry.digest_id;
      option.textContent = runLabel(entry);
      picker.appendChild(option);
    } else {
      const button = el("button", "older-run");
      button.type = "button";
      const target = entry.target || {};
      let label =
        (target.name || target.domain || entry.digest_id) +
        " · " +
        (entry.rating || entry.status) +
        " · " +
        fmtDateTime(entry.generated_at);
      if (entry.complete && entry.superseded_by) {
        label += " · superseded by " + entry.superseded_by;
      }
      if (entry.complete && entry.schema_valid === false) {
        label += " · invalid";
      }
      button.textContent = label;
      button.addEventListener("click", () => {
        $("older-runs").open = false;
        openRun(entry.digest_id).catch((err) => displayError(err));
        $("run-picker").value = "";
      });
      older.appendChild(button);
    }
  }
  const olderCount = (body.digests || []).length - mainCount;
  $("older-runs").hidden = olderCount === 0;
  $("older-summary").textContent =
    "Older / superseded / incomplete runs (" + olderCount + ")";
  if (runId) {
    const stillThere = [...picker.options].some((o) => o.value === runId);
    picker.value = stillThere ? runId : "";
  }
  if (autoselect) {
    const newest = (body.digests || []).find(
      (entry) => entry.complete && entry.authoritative
    );
    if (newest) {
      await openRun(newest.digest_id).catch((err) => displayError(err));
    }
  }
}

async function openRun(id) {
  resetRun();
  runId = id;
  runNarrativeValid = narrativeValidByDigest[id] ?? null;
  $("run-picker").value = id;
  $("empty-state").hidden = true;
  $("content").hidden = false;
  $("rail").hidden = false;
  buildRail();
  if (costByDigest[id] !== undefined && costByDigest[id] !== null) {
    runCost = costByDigest[id];
    updateTicker();
  }
  let digest;
  try {
    digest = await api(`/api/digests/${id}`);
  } catch (err) {
    if (statusByDigest[id] === "error") {
      openFailedRun(id).catch((e) =>
        e && e.isApiError ? showRailError(e.message) : displayError(e)
      );
    } else if (err && err.status === 404) {
      subscribe(id, false);
    } else if (err && err.isApiError) {
      showRailError(err.message);
    } else {
      displayError(err);
    }
    return;
  }
  try {
    renderFinal(digest);
  } catch (err) {
    displayError(err);
    return;
  }
  $("replay-btn").hidden = false;
}

/* ---- new digest drawer ---- */

function openDrawer() {
  $("drawer").hidden = false;
  $("form-error").hidden = true;
}

function closeDrawer() {
  $("drawer").hidden = true;
}

async function loadDemo() {
  const demo = await api("/api/demo-inputs");
  $("f-domain").value = demo.domain || "";
  $("f-company").value = demo.company || "";
  $("f-aliases").value = (demo.aliases || []).join(", ");
  $("f-employee").value = demo.employee_band || "";
  $("f-revenue").value = demo.revenue_band || "";
  $("f-speakers").value = (demo.speaker_names || []).join(", ");
  $("f-target").value = demo.target_speaker || "";
  $("f-asof").value = demo.as_of || "";
  const hints = $("demo-hints");
  hints.textContent =
    "Demo files:\n" +
    (demo.soc2 ? demo.soc2.path : "") +
    "\n" +
    (demo.interview ? demo.interview.path : "");
  hints.hidden = false;
}

async function uploadFile(input) {
  const file = input.files && input.files[0];
  if (!file) return null;
  const form = new FormData();
  form.append("file", file, file.name);
  return api("/api/uploads", { method: "POST", body: form });
}

function splitList(value) {
  return value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

async function submitDigest(event) {
  event.preventDefault();
  const error = $("form-error");
  error.hidden = true;
  const runBtn = $("run-btn");
  runBtn.disabled = true;
  runBtn.textContent = "Starting…";
  try {
    const soc2 = await uploadFile($("f-soc2"));
    const interview = await uploadFile($("f-interview"));
    const body = {
      domain: $("f-domain").value.trim(),
      company: $("f-company").value.trim(),
      aliases: splitList($("f-aliases").value),
      employee_band: $("f-employee").value.trim(),
      revenue_band: $("f-revenue").value.trim(),
      speaker_names: splitList($("f-speakers").value),
      target_speaker: $("f-target").value.trim(),
      demo: $("f-demo").checked,
    };
    if ($("f-asof").value) body.as_of = $("f-asof").value;
    if (soc2) body.soc2_upload_id = soc2.upload_id;
    if (interview) body.interview_upload_id = interview.upload_id;
    const posted = await api("/api/digests", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    closeDrawer();
    await loadRuns();
    openRunLive(posted.digest_id);
  } catch (err) {
    error.textContent = String(err.message || err);
    error.hidden = false;
  } finally {
    runBtn.disabled = false;
    runBtn.textContent = "Run";
  }
}

function openRunLive(id) {
  resetRun();
  runId = id;
  $("run-picker").value = "";
  $("empty-state").hidden = true;
  $("content").hidden = false;
  $("rail").hidden = false;
  buildRail();
  subscribe(id, false);
}

/* ---- run lifecycle ---- */

function resetRun() {
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }
  runNarrativeValid = null;
  if (verdictTimer) {
    clearInterval(verdictTimer);
    verdictTimer = null;
  }
  if (memoTimer) {
    clearInterval(memoTimer);
    memoTimer = null;
  }
  for (const timer of chipTimers) clearTimeout(timer);
  chipTimers = [];
  nextChipAt = 0;
  runId = null;
  streamDone = false;
  isReplay = false;
  evidence = { signals: 0, exceptions: 0, claims: 0, findings: 0 };
  interviewDurEl = null;
  seenSeq = new Set();
  verdictQueue = [];
  shownVerdicts = new Set();
  totalTokens = 0;
  runCost = null;
  evidenceById = {};
  findingById = {};
  groupEls = {};
  groupCounts = {};
  laneEls = {};
  crossCounts = { contradicted: 0, unsupported: 0, supported: 0 };
  adjustments = [];
  previewDigest = null;
  $("replay-btn").hidden = true;
  $("conn-status").hidden = true;
  $("rail-error").hidden = true;
  $("decision").replaceChildren();
  $("target-card").hidden = true;
  $("target-card").replaceChildren();
  $("evidence-panel").hidden = true;
  $("evidence-counters").replaceChildren();
  $("evidence-findings").replaceChildren();
  $("demo-note").hidden = true;
  $("plan").hidden = true;
  $("plan").replaceChildren();
  $("tool-groups").replaceChildren();
  $("lanes").replaceChildren();
  $("adjustments-toggle").hidden = true;
  $("adjustments").hidden = true;
  $("adjustments").replaceChildren();
  for (const id of [
    "summary-panel",
    "claims-panel",
    "risks-panel",
    "functions-panel",
    "soc2-panel",
    "plan-panel",
    "recs-panel",
    "questions-panel",
    "limitations-panel",
    "provenance",
    "export-wrap",
  ]) {
    $(id).hidden = true;
  }
  $("summary-body").replaceChildren();
  $("claims").replaceChildren();
  $("claims-note").hidden = true;
  $("risks").replaceChildren();
  $("functions").replaceChildren();
  $("soc2").replaceChildren();
  $("plan100").replaceChildren();
  $("recs").replaceChildren();
  $("questions").replaceChildren();
  $("limitations").replaceChildren();
  $("provenance").replaceChildren();
  updateTicker();
}

function buildRail() {
  const stages = $("stages");
  stages.replaceChildren();
  for (const stage of STAGES) {
    const li = el("li", null, STAGE_LABELS[stage]);
    li.dataset.stage = stage;
    stages.appendChild(li);
  }
}

function markStage(active) {
  const items = $("stages").children;
  let seenActive = false;
  for (const li of items) {
    li.classList.remove("active", "done");
    if (li.dataset.stage === active) {
      li.classList.add("active");
      seenActive = true;
    } else if (!seenActive) {
      li.classList.add("done");
    }
  }
}

function markRailDone() {
  for (const li of $("stages").children) {
    li.classList.remove("active");
    li.classList.add("done");
  }
}

function showRailError(message) {
  const railError = $("rail-error");
  railError.textContent = message;
  railError.hidden = false;
}

function subscribe(id, replay) {
  if (eventSource) eventSource.close();
  streamDone = false;
  isReplay = replay;
  let url = `/api/digests/${id}/events`;
  if (replay) url += "?replay=1";
  const conn = $("conn-status");
  conn.textContent = replay ? "replaying…" : "streaming…";
  conn.hidden = false;
  eventSource = new EventSource(url);
  eventSource.onmessage = (message) => {
    let event;
    try {
      event = JSON.parse(message.data);
    } catch (err) {
      showRailError("Bad event: " + err.message);
      return;
    }
    try {
      handleEvent(event);
    } catch (err) {
      displayError(err);
    }
  };
  eventSource.addEventListener("done", () => finishStream(true, ""));
  eventSource.addEventListener("error", (message) => {
    let detail = "run failed";
    try {
      detail = JSON.parse(message.data).error || detail;
    } catch (_) {
      /* keep default */
    }
    finishStream(false, detail);
  });
  eventSource.onerror = () => {
    if (!streamDone) {
      conn.textContent = "reconnecting…";
    }
  };
}

function finishStream(ok, detail) {
  streamDone = true;
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }
  $("conn-status").hidden = true;
  if (!ok) {
    showRailError(detail);
    return;
  }
  markRailDone();
  for (const lane of Object.values(laneEls)) {
    lane.classList.remove("running");
  }
  if (runId) {
    loadRuns().catch(() => {});
    api(`/api/digests/${runId}`)
      .then((digest) => {
        try {
          renderFinal(digest);
        } catch (err) {
          displayError(err);
          return;
        }
        $("replay-btn").hidden = false;
      })
      .catch((err) => {
        if (err && err.isApiError) showRailError(err.message);
        else displayError(err);
      });
  }
}

/* ---- live events (shared by live stream and replay) ---- */

function handleEvent(event) {
  if (event.seq !== undefined) {
    if (seenSeq.has(event.seq)) return;
    seenSeq.add(event.seq);
  }
  const type = event.type;
  if (type === "run_start") {
    renderTargetCard(event);
    $("evidence-panel").hidden = false;
    renderEvidence();
  } else if (type === "plan") {
    const plan = $("plan");
    plan.textContent = event.text || "";
    plan.hidden = false;
  } else if (type === "tool_call_start") {
    toolChip(event, true);
  } else if (type === "tool_call_end") {
    toolChip(event, false);
    evidence.signals += 1;
    renderEvidence();
  } else if (type === "stage") {
    markStage(event.stage);
    stageLane(event.stage);
  } else if (type === "model_turn_end") {
    addTokens(event.tokens);
    addCost(event.cost_usd);
  } else if (type === "submit_findings") {
    evidence.findings = event.count || 0;
    renderEvidence();
    renderSubmitted(event.findings || []);
  } else if (type === "engine_adjustment") {
    adjustments.push(event);
    renderAdjustments();
  } else if (type === "validation_error") {
    adjustments.push({ validation: true, ...event });
    renderAdjustments();
  } else if (type === "document_analysis_start") {
    ensureLane("doc", "Document analysis", true);
  } else if (type === "document_analysis_end") {
    addTokens(event.tokens);
    addCost(event.cost_usd);
    setLane("doc", "Document analysis", false,
      fmtDuration(event.duration_ms) +
        " · " +
        fmtTokensDict(event.tokens) +
        " · " +
        (event.finding_count || 0) +
        " findings");
    evidence.exceptions = event.exception_count || 0;
    renderEvidence();
  } else if (type === "transcription_start") {
    ensureLane("transcribe", "Transcription", true);
  } else if (type === "transcription_end") {
    addCost(event.cost_usd);
    const audio = Math.round(event.audio_seconds || 0) + "s audio";
    setLane("transcribe", "Transcription", false,
      event.cached
        ? "cached · " + audio
        : fmtDuration(event.duration_ms) + " · " + audio);
    if (interviewDurEl) {
      interviewDurEl.textContent =
        interviewDurEl.textContent + " · " + audio;
    }
  } else if (type === "claims_extracted") {
    addTokens(event.tokens);
    addCost(event.cost_usd);
    setLane("extract", "Claim extraction", false,
      (event.claim_count || 0) +
        " claims · " +
        fmtTokensDict(event.tokens));
    evidence.claims = event.claim_count || 0;
    renderEvidence();
  } else if (type === "crosscheck_verdict") {
    crossCounts[event.verdict] = (crossCounts[event.verdict] || 0) + 1;
    updateCrossLane();
    enqueueVerdict(event);
  } else if (type === "claims_merged") {
    setLane("crosscheck", "Cross-check", true,
      (event.before || 0) + "→" + (event.after || 0) + " merged");
  } else if (type === "scoring_complete") {
    setLane("scoring", "Scoring", false, "deterministic");
  } else if (type === "digest_preview") {
    renderPreview(event.digest);
  } else if (type === "crosscheck_complete") {
    addTokens(event.tokens);
    addCost(event.cost_usd);
    setLane("crosscheck", "Cross-check", false,
      fmtDuration(event.duration_ms) +
        " · " +
        fmtTokensDict(event.tokens) +
        " · " +
        (event.contradiction_count || 0) +
        " verdicts");
  } else if (type === "narrative_complete") {
    addTokens(event.usage);
    addCost(event.cost_usd);
    runNarrativeValid = event.valid;
    let meta =
      fmtDuration(event.duration_ms) +
      " · " +
      fmtTokensDict(event.usage) +
      " · " +
      (event.attempts || 1) +
      " attempt" +
      ((event.attempts || 1) > 1 ? "s" : "");
    if (event.attempts === 2 && event.first_attempt_errors) {
      meta += " · first failed: " + event.first_attempt_errors.join("; ");
    }
    setLane("narrative", "Narrative", false, meta);
  } else if (type === "digest_final") {
    renderFinal(event.digest);
  } else if (type === "run_end") {
    const usage = event.usage || {};
    if (usage.estimated_cost_usd !== undefined) {
      runCost = usage.estimated_cost_usd;
      updateTicker();
    }
  }
}

function renderTargetCard(event) {
  const card = $("target-card");
  card.replaceChildren();
  card.hidden = false;
  card.appendChild(
    el(
      "div",
      "target-title",
      (event.company_name || "?") + " · " + (event.domain || "?")
    )
  );
  const bits = [];
  if (event.industry) bits.push(event.industry);
  if (event.employee_band) bits.push(event.employee_band + " employees");
  if (event.revenue_band) bits.push("$" + event.revenue_band + " revenue");
  if (bits.length) card.appendChild(el("div", "target-sub", bits.join(" · ")));
  const chips = el("div", "target-chips");
  chips.appendChild(el("span", "src-chip", "Outside-in"));
  if (event.soc2_filename) {
    chips.appendChild(
      el("span", "src-chip", "SOC 2 report · " + event.soc2_filename)
    );
  }
  if (event.interview_filename) {
    interviewDurEl = el(
      "span",
      "src-chip",
      "Management interview · " + event.interview_filename
    );
    chips.appendChild(interviewDurEl);
  }
  card.appendChild(chips);
}

function renderEvidence() {
  const wrap = $("evidence-counters");
  wrap.replaceChildren();
  const cells = [
    [evidence.signals, "signals collected"],
    [evidence.exceptions, "SOC 2 exceptions"],
    [evidence.claims, "claims extracted"],
    [evidence.findings, "findings submitted"],
  ];
  for (const [value, label] of cells) {
    const cell = el("div", "ev-stat");
    cell.appendChild(el("div", "ev-num", String(value)));
    cell.appendChild(el("div", "ev-label", label));
    wrap.appendChild(cell);
  }
}

function renderSubmitted(briefs) {
  const list = $("evidence-findings");
  list.replaceChildren();
  for (const brief of briefs) {
    const item = el("li");
    item.appendChild(sevBadge(brief.severity));
    item.appendChild(el("span", null, " " + (brief.title || brief.finding_id || "?")));
    list.appendChild(item);
  }
}

function finishChip(chip, event) {
  chip.classList.remove("running");
  chip.classList.add(event.status === "error" ? "error" : "done");
  chip.textContent = "";
  chip.appendChild(el("span", null, event.tool || "?"));
  if (event.served_from_fixture) {
    chip.appendChild(el("span", "fixture-tag", " fixture"));
    $("demo-note").hidden = false;
  } else {
    chip.appendChild(el("span", "dur", " " + fmtDuration(event.duration_ms)));
  }
}

function toolChip(event, running) {
  const group = String(event.parallel_group ?? 0);
  let wrap = groupEls[group];
  if (!wrap) {
    wrap = el("div", "tool-group");
    const label = el("div", "group-label");
    wrap.appendChild(label);
    wrap.appendChild(el("div", "chips"));
    groupEls[group] = wrap;
    groupCounts[group] = 0;
    $("tool-groups").appendChild(wrap);
  }
  const chips = wrap.querySelector(".chips");
  const key = (event.tool || "?") + "|" + group;
  let chip = chips.querySelector('[data-key="' + key + '"]');
  if (!chip) {
    chip = el("span", "chip running", event.tool || "?");
    chip.dataset.key = key;
    chips.appendChild(chip);
    groupCounts[group] += 1;
    wrap.querySelector(".group-label").textContent =
      "group " + group + " · parallel ×" + groupCounts[group];
  }
  if (!running) {
    if (isReplay && !REDUCED_MOTION) {
      const now = Date.now();
      nextChipAt = Math.max(now, nextChipAt + 400);
      const target = chip;
      const snapshot = { ...event };
      chipTimers.push(
        setTimeout(() => finishChip(target, snapshot), nextChipAt - now)
      );
    } else {
      finishChip(chip, event);
    }
  }
}

function ensureLane(key, name, running) {
  if (laneEls[key]) {
    if (running) laneEls[key].classList.add("running");
    return laneEls[key];
  }
  const lane = el("div", "lane" + (running ? " running" : ""));
  lane.appendChild(el("span", "lane-name", name));
  lane.appendChild(el("span", "lane-meta", running ? "running…" : ""));
  laneEls[key] = lane;
  $("lanes").appendChild(lane);
  return lane;
}

function setLane(key, name, running, meta) {
  const lane = ensureLane(key, name, running);
  lane.classList.toggle("running", running);
  lane.querySelector(".lane-meta").textContent = meta;
}

function stageLane(stage) {
  if (stage === "analyzing_documents") ensureLane("doc", "Document analysis", true);
  else if (stage === "transcribing") ensureLane("transcribe", "Transcription", true);
  else if (stage === "cross_checking") {
    ensureLane("crosscheck", "Cross-check", true);
    updateCrossLane();
  } else if (stage === "scoring") ensureLane("scoring", "Scoring", true);
  else if (stage === "writing_narrative") ensureLane("narrative", "Narrative", true);
  else if (stage === "complete") markRailDone();
}

function updateCrossLane() {
  const lane = ensureLane("crosscheck", "Cross-check", true);
  const parts = [];
  for (const verdict of ["contradicted", "unsupported", "supported"]) {
    if (crossCounts[verdict]) parts.push(crossCounts[verdict] + " " + verdict);
  }
  lane.querySelector(".lane-meta").textContent =
    parts.length ? parts.join(" · ") : "running…";
}

function renderAdjustments() {
  const toggle = $("adjustments-toggle");
  const list = $("adjustments");
  toggle.hidden = false;
  toggle.textContent = "Engine adjustments (" + adjustments.length + ")";
  list.replaceChildren();
  for (const adj of adjustments) {
    let text;
    let hot = false;
    if (adj.validation) {
      text = "dropped " + (adj.finding_id || "?") + ": validation failed";
    } else {
      text =
        (adj.finding_id || "?") +
        " " +
        (adj.field || "?") +
        " " +
        JSON.stringify(adj.from) +
        "→" +
        JSON.stringify(adj.to) +
        " (" +
        (adj.reason || "?") +
        ")";
      hot =
        adj.reason === "max_confidence" ||
        adj.reason === "cost_override" ||
        adj.reason === "cost_band";
    }
    list.appendChild(el("li", hot ? "hot" : null, text));
  }
}

/* ---- verdict cards (staggered, severity order) ---- */

function verdictRank(item) {
  const verdict = item.verdict || item.event?.verdict || "unsupported";
  const severity = item.severity || item.event?.severity || "info";
  return [
    VERDICT_RANK[verdict] ?? 1,
    SEVERITY_RANK[severity] ?? 4,
    item.contradiction_id || item.event?.contradiction_id || "",
  ];
}

function compareVerdicts(a, b) {
  const ra = verdictRank(a);
  const rb = verdictRank(b);
  for (let i = 0; i < 3; i++) {
    if (ra[i] < rb[i]) return -1;
    if (ra[i] > rb[i]) return 1;
  }
  return 0;
}

function enqueueVerdict(event) {
  const id = event.contradiction_id;
  if (!id || shownVerdicts.has(id)) return;
  verdictQueue.push({ event });
  verdictQueue.sort(compareVerdicts);
  $("claims-panel").hidden = false;
  if (REDUCED_MOTION) {
    drainVerdicts();
    return;
  }
  if (!verdictTimer) {
    showNextVerdict();
    verdictTimer = setInterval(showNextVerdict, 450);
  }
}

function showNextVerdict() {
  const next = verdictQueue.shift();
  if (!next) {
    if (verdictTimer) {
      clearInterval(verdictTimer);
      verdictTimer = null;
    }
    return;
  }
  const event = next.event;
  shownVerdicts.add(event.contradiction_id);
  $("claims").appendChild(verdictCardLive(event));
}

function drainVerdicts() {
  while (verdictQueue.length) showNextVerdict();
}

function sevBadge(severity) {
  return el("span", "sev sev-" + (severity || "info"), severity || "info");
}

function scrollToCite(ref) {
  const target = $(ref.startsWith("F-") ? "finding-" + ref : "claim-" + ref);
  if (!target) return;
  target.scrollIntoView({
    block: "nearest",
    behavior: REDUCED_MOTION ? "auto" : "smooth",
  });
  target.classList.remove("flash-target");
  void target.offsetWidth;
  target.classList.add("flash-target");
  setTimeout(() => target.classList.remove("flash-target"), 1500);
}

function appendCitedText(container, text) {
  CITE_RE.lastIndex = 0;
  let last = 0;
  let match;
  while ((match = CITE_RE.exec(text || "")) !== null) {
    if (match.index > last) {
      container.appendChild(
        document.createTextNode(text.slice(last, match.index))
      );
    }
    const ref = match[1];
    const chip = el("button", "cite-chip", ref);
    chip.type = "button";
    chip.addEventListener("click", () => scrollToCite(ref));
    container.appendChild(chip);
    last = match.index + match[0].length;
  }
  if (last < (text || "").length) {
    container.appendChild(document.createTextNode(text.slice(last)));
  }
}

function verdictBadge(verdict) {
  return el(
    "span",
    "sev verdict-" + (verdict || "unsupported"),
    verdict || "unsupported"
  );
}

function evidenceChip(evidence) {
  let label = METHOD_LABELS[evidence.collection_method] || evidence.collector || "Evidence";
  if (evidence.collection_method === "document_upload" && evidence.locator) {
    const match = CONTROL_RE.exec(evidence.locator);
    if (match) label += " " + match[1];
  }
  return el("span", "src-chip", label);
}

function evidenceBlock(evidence, finding) {
  const wrap = el("div", "ev-item");
  wrap.appendChild(evidenceChip(evidence));
  wrap.appendChild(el("span", null, finding ? finding.title + " · " : ""));
  wrap.appendChild(el("span", null, evidence.excerpt || ""));
  const loc = el("span", "loc", evidence.locator || "");
  wrap.appendChild(loc);
  return wrap;
}

function resolveRef(ref) {
  if (ref.startsWith("F-")) {
    const finding = findingById[ref];
    if (!finding) return null;
    return { finding };
  }
  const evidence = evidenceById[ref];
  if (!evidence) return null;
  return { evidence, finding: findingById[evidence.finding_id] };
}

function verdictCardLive(event) {
  const card = el("div", "claim-card" + (REDUCED_MOTION ? "" : " enter"));
  if (event.contradiction_id) card.id = "claim-" + event.contradiction_id;
  if (event.verdict === "supported") card.classList.add("supported");
  const head = el("div", "claim-head");
  head.appendChild(el("span", "cid", event.contradiction_id || ""));
  head.appendChild(verdictBadge(event.verdict));
  head.appendChild(sevBadge(event.severity));
  head.appendChild(el("span", "spacer"));
  head.appendChild(el("span", "cid", "claim #" + (event.claim_index ?? "?")));
  card.appendChild(head);
  const cols = el("div", "claim-cols");
  const said = el("div", "claim-said");
  said.appendChild(el("h4", null, "Management said"));
  said.appendChild(el("p", "claim-quote", event.text || ""));
  cols.appendChild(said);
  const shows = el("div");
  shows.appendChild(el("h4", null, "Evidence shows"));
  shows.appendChild(el("p", "claim-quote", event.excerpt || "—"));
  cols.appendChild(shows);
  card.appendChild(cols);
  const refs = el("div", "claim-refs", (event.refs || []).join(" · "));
  card.appendChild(refs);
  return card;
}

function verdictCardFull(contra) {
  const card = el("div", "claim-card");
  if (contra.contradiction_id) card.id = "claim-" + contra.contradiction_id;
  if (contra.verdict === "supported") card.classList.add("supported");
  const head = el("div", "claim-head");
  head.appendChild(el("span", "cid", contra.contradiction_id || ""));
  head.appendChild(verdictBadge(contra.verdict));
  head.appendChild(sevBadge(contra.severity));
  card.appendChild(head);
  const cols = el("div", "claim-cols");
  const said = el("div", "claim-said");
  said.appendChild(el("h4", null, "Management said"));
  const claim = contra.claim || {};
  said.appendChild(el("p", "claim-quote", claim.text || ""));
  said.appendChild(
    el("div", "claim-meta", (claim.speaker || "?") + " · " + (claim.timestamp || "?"))
  );
  cols.appendChild(said);
  const shows = el("div");
  shows.appendChild(el("h4", null, "Evidence shows"));
  let shown = 0;
  for (const ref of contra.evidence_refs || []) {
    const resolved = resolveRef(ref);
    if (!resolved) continue;
    if (resolved.evidence) {
      shows.appendChild(evidenceBlock(resolved.evidence, null));
    } else {
      const f = resolved.finding;
      const item = el("div", "ev-item");
      item.appendChild(el("span", "src-chip", f.finding_id));
      item.appendChild(sevBadge(f.severity));
      item.appendChild(el("span", null, " " + f.title));
      shows.appendChild(item);
    }
    shown += 1;
  }
  if (!shown) shows.appendChild(el("p", "claim-quote", "No linked evidence."));
  if (contra.explanation) {
    shows.appendChild(el("p", "deal-impact", contra.explanation));
  }
  cols.appendChild(shows);
  card.appendChild(cols);
  const refs = el("div", "claim-refs", (contra.evidence_refs || []).join(" · "));
  card.appendChild(refs);
  return card;
}

function renderClaimsFinal(contradictions) {
  if (verdictTimer) {
    clearInterval(verdictTimer);
    verdictTimer = null;
  }
  verdictQueue = [];
  shownVerdicts = new Set();
  const wrap = $("claims");
  wrap.replaceChildren();
  const ordered = [...(contradictions || [])].sort(compareVerdicts);
  for (const contra of ordered) {
    shownVerdicts.add(contra.contradiction_id);
    wrap.appendChild(verdictCardFull(contra));
  }
}

/* ---- digest rendering ---- */

function indexDigest(digest) {
  evidenceById = {};
  findingById = {};
  for (const finding of digest.findings || []) {
    findingById[finding.finding_id] = finding;
    for (const evidence of finding.evidence || []) {
      evidenceById[evidence.evidence_id] = {
        ...evidence,
        finding_id: finding.finding_id,
      };
    }
  }
  for (const evidence of digest.supporting_evidence || []) {
    if (evidence.evidence_id && !evidenceById[evidence.evidence_id]) {
      evidenceById[evidence.evidence_id] = { ...evidence, finding_id: null };
    }
  }
}

function confidenceBasis(digest) {
  const inputs = digest.inputs || {};
  const parts = [];
  if (inputs.domain_scan) parts.push("outside-in scan");
  if ((inputs.documents || []).length) parts.push("SOC 2 report");
  if ((inputs.interviews || []).length) parts.push("management interview");
  return parts.length ? parts.join(" + ") : "no inputs";
}

function renderDecision(digest, flash) {
  const overall = digest.overall || {};
  const target = digest.target || {};
  const plan = digest.remediation_plan || {};
  const box = $("decision");
  box.replaceChildren();
  const top = el("div", "dec-top");
  top.appendChild(el("div", "rating-badge", overall.rating || "?"));
  const titleBox = el("div");
  titleBox.appendChild(
    el("div", "dec-title", (target.name || "?") + " · " + (target.domain || "?"))
  );
  titleBox.appendChild(
    el(
      "div",
      "dec-sub",
      (digest.generated_at || "").slice(0, 10) + " · " + (digest.digest_id || "")
    )
  );
  top.appendChild(titleBox);
  box.appendChild(top);
  const grid = el("div", "dec-grid");
  const cells = [
    ["Score", Number(overall.score ?? 0).toFixed(1)],
    ["Decision", DEAL_LABELS[overall.deal_signal] || overall.deal_signal || "—"],
    ["Confidence", (overall.confidence || "—") + " · " + confidenceBasis(digest)],
    ["Remediation", fmtRange(plan.total_cost_low_usd || 0, plan.total_cost_high_usd || 0)],
  ];
  for (const [key, value] of cells) {
    const cell = el("div");
    cell.appendChild(el("div", "k", key));
    cell.appendChild(el("div", "v", value));
    grid.appendChild(cell);
  }
  const costCell = el("div");
  costCell.appendChild(el("div", "k", "Run cost"));
  const costValue = el("div", "v", fmtCost(runCost));
  costValue.id = "dec-cost";
  costCell.appendChild(costValue);
  grid.appendChild(costCell);
  box.appendChild(grid);
  const caps = overall.rating_caps_applied || [];
  if (caps.length) {
    const chips = el("div", "cap-chips");
    for (const cap of caps) {
      const chip = el("span", "cap-chip", CAP_LABELS[cap] || cap);
      chip.title = cap;
      chips.appendChild(chip);
    }
    box.appendChild(chips);
  }
  if (flash && !REDUCED_MOTION) {
    box.classList.remove("flash");
    void box.offsetWidth;
    box.classList.add("flash");
  }
}

function startMemoTimer() {
  memoStart = Date.now();
  const tick = () => {
    const secs = Math.floor((Date.now() - memoStart) / 1000);
    for (const id of ["summary-body", "recs"]) {
      const writing = $(id).querySelector(".memo-writing .timer");
      if (writing) writing.textContent = secs + "s";
    }
  };
  if (memoTimer) clearInterval(memoTimer);
  memoTimer = setInterval(tick, 1000);
}

function memoPlaceholder() {
  const wrap = el("div", "memo-writing", "Writing IC memo… ");
  wrap.appendChild(el("span", "timer", "0s"));
  return wrap;
}

function renderPreview(digest) {
  previewDigest = digest;
  $("evidence-panel").hidden = true;
  indexDigest(digest);
  renderDecision(digest, true);
  $("summary-panel").hidden = false;
  $("summary-body").replaceChildren(memoPlaceholder());
  $("recs-panel").hidden = false;
  $("recs").replaceChildren(memoPlaceholder());
  startMemoTimer();
  const hasInterview = (digest.inputs?.interviews || []).length > 0;
  $("claims-panel").hidden = false;
  const note = $("claims-note");
  if (!hasInterview) {
    note.textContent = "Not provided — no management interview in this run.";
    note.hidden = false;
  }
  renderRisks(digest);
  renderFunctions(digest);
  renderSoc2(digest);
  renderPlan(digest);
  renderLimitations(digest);
  renderProvenance(digest);
}

function renderFinal(digest) {
  if (memoTimer) {
    clearInterval(memoTimer);
    memoTimer = null;
  }
  indexDigest(digest);
  renderDecision(digest, !previewDigest);
  previewDigest = digest;
  const narrative = digest.narrative || {};
  $("summary-panel").hidden = false;
  const summaryBody = el("p");
  appendCitedText(summaryBody, narrative.executive_summary || "");
  $("summary-body").replaceChildren(summaryBody);
  if (runNarrativeValid === false) {
    const warning = el(
      "div",
      "warning",
      "Warning: narrative validation failed — prose may contain " +
        "errors. See the trace for details."
    );
    $("summary-body").prepend(warning);
  }
  const hasInterview = (digest.inputs?.interviews || []).length > 0;
  $("claims-panel").hidden = false;
  $("claims-note").hidden = hasInterview;
  if (!hasInterview) {
    $("claims-note").textContent =
      "Not provided — no management interview in this run.";
    $("claims").replaceChildren();
  } else {
    renderClaimsFinal(digest.contradictions);
  }
  renderRisks(digest);
  renderFunctions(digest);
  renderSoc2(digest);
  renderPlan(digest);
  renderRecs(digest);
  renderQuestions(digest);
  renderLimitations(digest);
  renderProvenance(digest);
  if (runId) {
    const link = $("export-memo");
    link.href = `/api/digests/${runId}/memo`;
    link.setAttribute("download", runId + "_memo.md");
    $("export-wrap").hidden = false;
  }
}

function renderRisks(digest) {
  $("risks-panel").hidden = false;
  const wrap = $("risks");
  wrap.replaceChildren();
  const findings = [...(digest.findings || [])].sort((a, b) => {
    const rank =
      (SEVERITY_RANK[a.severity] ?? 4) - (SEVERITY_RANK[b.severity] ?? 4);
    return rank || String(a.finding_id).localeCompare(String(b.finding_id));
  });
  for (const finding of findings) {
    const row = el("div", "risk-row");
    if (finding.finding_id) row.id = "finding-" + finding.finding_id;
    const head = el("button", "risk-head");
    head.type = "button";
    head.appendChild(sevBadge(finding.severity));
    const title = el("span", "risk-title", finding.title || "");
    title.appendChild(el("span", "risk-id", "  " + (finding.finding_id || "")));
    head.appendChild(title);
    head.appendChild(
      el("span", "src-chip", SOURCE_LABELS[finding.source] || finding.source || "")
    );
    const remediation = finding.remediation || {};
    head.appendChild(
      el(
        "span",
        "risk-cost",
        fmtRange(remediation.cost_low_usd || 0, remediation.cost_high_usd || 0)
      )
    );
    const detail = el("div", "risk-detail");
    detail.hidden = true;
    for (const evidence of finding.evidence || []) {
      detail.appendChild(evidenceBlock(evidence, null));
      const method = el("div", "claim-meta");
      method.textContent = "via " + (evidence.collection_method || "?");
      detail.appendChild(method);
    }
    if (finding.deal_impact) {
      detail.appendChild(el("p", "deal-impact", finding.deal_impact));
    }
    if (remediation.summary) {
      detail.appendChild(el("p", "deal-impact", "Fix: " + remediation.summary));
    }
    head.addEventListener("click", () => {
      detail.hidden = !detail.hidden;
    });
    row.appendChild(head);
    row.appendChild(detail);
    wrap.appendChild(row);
  }
}

function renderFunctions(digest) {
  $("functions-panel").hidden = false;
  const wrap = $("functions");
  wrap.replaceChildren();
  for (const entry of digest.function_scores || []) {
    const row = el(
      "div",
      "fn-row" + (entry.assessed ? "" : " unassessed")
    );
    row.appendChild(
      el("span", null, (FUNCTION_NAMES[entry.function] || entry.function) +
        "  ")
    );
    const bar = el("div", "fn-bar");
    const fill = el("div", "fn-fill");
    fill.style.width = (entry.assessed ? Math.max(0, entry.score || 0) : 100) + "%";
    bar.appendChild(fill);
    row.appendChild(bar);
    row.appendChild(
      el(
        "span",
        "fn-score",
        entry.assessed ? Number(entry.score ?? 0).toFixed(1) : "—"
      )
    );
    if (!entry.assessed) {
      row.appendChild(el("span", "fn-na", "Not assessed"));
    }
    wrap.appendChild(row);
  }
}

function renderSoc2(digest) {
  $("soc2-panel").hidden = false;
  const wrap = $("soc2");
  wrap.replaceChildren();
  const soc2 = digest.soc2_analysis;
  if (!soc2) {
    wrap.appendChild(el("p", "muted", "Not provided — no SOC 2 report in this run."));
    return;
  }
  const kv = el("dl", "kv");
  const rows = [
    ["Opinion", soc2.opinion],
    ["Period", (soc2.period_start || "") + " → " + (soc2.period_end || "")],
    ["Auditor", soc2.auditor],
    ["Bridge gap", (soc2.bridge_gap_days ?? "?") + " days"],
    ["CUECs", String((soc2.cuecs || []).length)],
  ];
  for (const [key, value] of rows) {
    kv.appendChild(el("dt", null, key));
    kv.appendChild(el("dd", null, value));
  }
  wrap.appendChild(kv);
  if ((soc2.exceptions || []).length) {
    wrap.appendChild(el("h4", null, "Exceptions"));
    const table = el("table", "mini");
    const head = el("tr");
    for (const h of ["Control", "Description", "Deviations", "Finding"]) {
      head.appendChild(el("th", null, h));
    }
    table.appendChild(head);
    for (const exc of soc2.exceptions) {
      const tr = el("tr");
      tr.appendChild(el("td", "mono", exc.control_id || ""));
      tr.appendChild(el("td", null, exc.description || ""));
      const counts =
        exc.deviations === null || exc.deviations === undefined
          ? "n/s"
          : exc.deviations + "/" + (exc.sample_size ?? "n/s");
      tr.appendChild(el("td", "mono", counts));
      tr.appendChild(el("td", "mono", exc.finding_id || "—"));
      table.appendChild(tr);
    }
    wrap.appendChild(table);
  }
  if ((soc2.subservice_orgs || []).length) {
    wrap.appendChild(el("h4", null, "Carve-outs"));
    const table = el("table", "mini");
    const head = el("tr");
    for (const h of ["Org", "Method", "Critical"]) {
      head.appendChild(el("th", null, h));
    }
    table.appendChild(head);
    for (const org of soc2.subservice_orgs) {
      const tr = el("tr");
      tr.appendChild(el("td", null, org.name || ""));
      tr.appendChild(el("td", null, org.method || ""));
      tr.appendChild(el("td", null, org.critical ? "yes" : "no"));
      table.appendChild(tr);
    }
    wrap.appendChild(table);
  }
}

function renderPlan(digest) {
  $("plan-panel").hidden = false;
  const wrap = $("plan100");
  wrap.replaceChildren();
  const plan = digest.remediation_plan || {};
  const items = plan.items || [];
  const cols = el("div", "plan-cols");
  for (const window of WINDOW_ORDER) {
    const col = el("div", "plan-col");
    col.appendChild(el("h4", null, WINDOW_LABELS[window]));
    let low = 0;
    let high = 0;
    for (const item of items.filter((i) => i.window === window)) {
      low += item.cost_low_usd || 0;
      high += item.cost_high_usd || 0;
      const box = el("div", "plan-item");
      box.appendChild(el("div", null, item.action || ""));
      box.appendChild(
        el(
          "div",
          "mono",
          (item.finding_ids || []).join(", ") +
            " · " +
            (item.owner_role || "") +
            " · " +
            fmtRange(item.cost_low_usd || 0, item.cost_high_usd || 0)
        )
      );
      col.appendChild(box);
    }
    col.appendChild(el("div", "plan-total", "Subtotal " + fmtRange(low, high)));
    cols.appendChild(col);
  }
  wrap.appendChild(cols);
  wrap.appendChild(
    el(
      "div",
      "plan-total",
      "Total " +
        fmtRange(plan.total_cost_low_usd || 0, plan.total_cost_high_usd || 0)
    )
  );
}

function renderRecs(digest) {
  $("recs-panel").hidden = false;
  const wrap = $("recs");
  wrap.replaceChildren();
  const groups = {};
  const order = [];
  for (const rec of digest.deal_recommendations || []) {
    if (!groups[rec.type]) {
      groups[rec.type] = [];
      order.push(rec.type);
    }
    groups[rec.type].push(rec);
  }
  for (const type of order) {
    const group = el("div", "rec-group");
    group.appendChild(el("h4", null, REC_LABELS[type] || type));
    for (const rec of groups[type]) {
      const recPara = el("p", "rec");
      appendCitedText(recPara, rec.text || "");
      group.appendChild(recPara);
      group.appendChild(
        el("div", "rec-basis", "basis: " + (rec.basis_ids || []).join(", "))
      );
    }
    wrap.appendChild(group);
  }
}

function renderQuestions(digest) {
  const questions =
    (digest.narrative || {}).key_questions_for_management || [];
  $("questions-panel").hidden = false;
  const wrap = $("questions");
  wrap.replaceChildren();
  for (const question of questions) {
    const item = el("li");
    appendCitedText(item, question);
    wrap.appendChild(item);
  }
}

function renderLimitations(digest) {
  $("limitations-panel").hidden = false;
  const wrap = $("limitations");
  wrap.replaceChildren();
  for (const line of digest.limitations || []) {
    wrap.appendChild(el("li", null, line));
  }
}

function renderProvenance(digest) {
  $("provenance").hidden = false;
  const wrap = $("provenance");
  wrap.replaceChildren();
  const inputs = digest.inputs || {};
  const lines = [];
  lines.push("digest " + (digest.digest_id || "?"));
  for (const doc of inputs.documents || []) {
    lines.push(
      "doc " + (doc.filename || "?") + " sha256:" + (doc.sha256 || "").slice(0, 12)
    );
  }
  for (const iv of inputs.interviews || []) {
    lines.push(
      "interview " + (iv.filename || "?") + " sha256:" + (iv.sha256 || "").slice(0, 12)
    );
  }
  for (const provider of (digest.mode || {}).providers || []) {
    lines.push("model " + provider.role + ": " + provider.model);
  }
  lines.push("run cost " + fmtCost(runCost));
  lines.push("Generated by PE Risk Key");
  for (const line of lines) {
    wrap.appendChild(el("div", null, line));
  }
}

/* ---- replay + failed runs ---- */

function replayRun() {
  if (!runId) return;
  const id = runId;
  const keepPicker = $("run-picker").value;
  resetRun();
  runId = id;
  $("run-picker").value = keepPicker;
  $("empty-state").hidden = true;
  $("content").hidden = false;
  $("rail").hidden = false;
  buildRail();
  subscribe(id, true);
}

async function openFailedRun(id) {
  resetRun();
  runId = id;
  $("empty-state").hidden = true;
  $("content").hidden = false;
  $("rail").hidden = false;
  buildRail();
  let body;
  try {
    body = await api(`/api/digests/${id}/trace`);
  } catch (err) {
    if (err && err.isApiError) showRailError(err.message);
    else displayError(err);
    return;
  }
  try {
    for (const event of body.events || []) {
      handleEvent(event);
    }
  } catch (err) {
    displayError(err);
    return;
  }
  showRailError("Run failed before producing a digest.");
}

/* ---- boot ---- */

function boot() {
  if (PRESENT) document.body.classList.add("present");
  $("new-digest-btn").addEventListener("click", openDrawer);
  $("drawer-cancel").addEventListener("click", closeDrawer);
  $("load-demo-btn").addEventListener("click", () => {
    loadDemo().catch((err) => {
      const error = $("form-error");
      error.textContent = String(err.message || err);
      error.hidden = false;
    });
  });
  $("digest-form").addEventListener("submit", submitDigest);
  $("run-picker").addEventListener("change", (event) => {
    const id = event.target.value;
    if (id) openRun(id).catch((err) => displayError(err));
  });
  $("replay-btn").addEventListener("click", replayRun);
  $("adjustments-toggle").addEventListener("click", () => {
    $("adjustments").hidden = !$("adjustments").hidden;
  });
  loadRuns(true).catch((err) => {
    if (err && err.isApiError) {
      $("empty-state").textContent = err.message;
    } else {
      console.error((err && err.stack) || err);
      $("empty-state").textContent =
        "Display error: " + String((err && err.message) || err);
    }
  });
}

boot();
