const form = document.getElementById("lookup-form");
const iocInput = document.getElementById("ioc-input");
const debugInput = document.getElementById("debug-input");
const lookupButton = document.getElementById("lookup-btn");
const statusLine = document.getElementById("status-line");
const summaryPanel = document.getElementById("summary-panel");
const cacheChip = document.getElementById("cache-chip");
const metricIoc = document.getElementById("metric-ioc");
const metricType = document.getElementById("metric-type");
const metricScore = document.getElementById("metric-score");
const metricLevel = document.getElementById("metric-level");
const categoriesList = document.getElementById("categories-list");
const sourcesGrid = document.getElementById("sources-grid");
const jsonOutput = document.getElementById("json-output");
const exampleChips = document.querySelectorAll(".example-chip");

function setStatus(message, type = "muted") {
  statusLine.textContent = message;
  if (type === "error") {
    statusLine.style.color = "#b22f2b";
    return;
  }
  if (type === "success") {
    statusLine.style.color = "#0f7b57";
    return;
  }
  statusLine.style.color = "#5f737d";
}

function levelClass(level) {
  if (!level) return "";
  return `risk-${String(level).toLowerCase()}`;
}

function toList(value) {
  return Array.isArray(value) ? value : [];
}

function renderCategories(categories) {
  categoriesList.innerHTML = "";
  const list = toList(categories);
  if (list.length === 0) {
    const empty = document.createElement("span");
    empty.className = "category-chip";
    empty.textContent = "none";
    categoriesList.appendChild(empty);
    return;
  }
  for (const category of list) {
    const chip = document.createElement("span");
    chip.className = "category-chip";
    chip.textContent = String(category);
    categoriesList.appendChild(chip);
  }
}

function renderSourceCards(sources, debug) {
  sourcesGrid.innerHTML = "";
  const list = toList(sources);
  if (list.length === 0) {
    sourcesGrid.innerHTML = "<p>Aucune source retournee.</p>";
    return;
  }

  for (const source of list) {
    const card = document.createElement("article");
    const status = source?.status === "ok" ? "ok" : "error";
    card.className = `source-card status-${status}`;

    const sourceName = String(source?.source || "unknown");
    const sourceData = source?.data && typeof source.data === "object" ? source.data : {};
    const score = Number.isFinite(sourceData.score) ? sourceData.score : "-";
    const duration = Number.isFinite(source?.duration_ms) ? source.duration_ms : "-";
    const sourceCategories = toList(sourceData.categories).join(", ") || "-";
    const error = source?.error ? String(source.error) : "";

    card.innerHTML = `
      <div class="source-head">
        <h3 class="source-title">${sourceName}</h3>
        <span class="source-status ${status}">${status}</span>
      </div>
      <p class="source-meta"><strong>score:</strong> ${score}</p>
      <p class="source-meta"><strong>duration:</strong> ${duration} ms</p>
      <p class="source-meta"><strong>categories:</strong> ${sourceCategories}</p>
      ${error ? `<p class="source-error"><strong>error:</strong> ${error}</p>` : ""}
    `;

    if (debug && source.raw_json !== undefined) {
      const details = document.createElement("details");
      const summary = document.createElement("summary");
      summary.textContent = "raw_json";
      const pre = document.createElement("pre");
      pre.textContent = JSON.stringify(source.raw_json, null, 2);
      details.appendChild(summary);
      details.appendChild(pre);
      card.appendChild(details);
    }

    sourcesGrid.appendChild(card);
  }
}

function renderSummary(payload, debug) {
  summaryPanel.classList.remove("hidden");

  metricIoc.textContent = payload?.ioc || "-";
  metricType.textContent = payload?.ioc_type || "-";
  metricScore.textContent = Number.isFinite(payload?.risk_score) ? String(payload.risk_score) : "-";

  const level = String(payload?.risk_level || "-");
  metricLevel.className = "metric-value risk-badge";
  if (level !== "-") {
    metricLevel.classList.add(levelClass(level));
  }
  metricLevel.textContent = level;

  renderCategories(payload?.categories);
  renderSourceCards(payload?.sources, debug);

  const cacheHit = payload?.debug?.cache_hit === true;
  cacheChip.classList.toggle("hidden", !cacheHit);

  jsonOutput.textContent = JSON.stringify(payload, null, 2);
}

async function lookupIoc(ioc, debug) {
  const encoded = encodeURIComponent(ioc);
  const endpoint = `/lookup/${encoded}${debug ? "?debug=true" : ""}`;
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), 25000);

  try {
    const response = await fetch(endpoint, {
      method: "GET",
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    return payload;
  } finally {
    window.clearTimeout(timeoutId);
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const ioc = iocInput.value.trim();
  if (!ioc) {
    setStatus("IOC invalide: saisis une valeur.", "error");
    iocInput.focus();
    return;
  }

  lookupButton.disabled = true;
  setStatus("Analyse en cours...");

  try {
    const payload = await lookupIoc(ioc, debugInput.checked);
    renderSummary(payload, debugInput.checked);
    setStatus("Analyse terminee.", "success");
  } catch (error) {
    jsonOutput.textContent = "";
    sourcesGrid.innerHTML = "";
    summaryPanel.classList.add("hidden");
    setStatus(`Echec de l'analyse: ${error.message}`, "error");
  } finally {
    lookupButton.disabled = false;
  }
});

for (const chip of exampleChips) {
  chip.addEventListener("click", () => {
    iocInput.value = chip.dataset.ioc || "";
    iocInput.focus();
  });
}
