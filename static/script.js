(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);

  const analyzeForm = $("analyze-form");
  const urlInput = $("analyzer-input");
  const analyzeBtn = $("analyze-btn");
  const btnText = analyzeBtn.querySelector(".btn-text");
  const btnLoader = analyzeBtn.querySelector(".btn-loader");
  const clearInputBtn = $("clear-input-btn");
  const inputError = $("input-error");
  const liveRegion = $("live-region");
  const resultsSection = $("results-section");
  const verdictBadge = $("verdict-badge");
  const displayUrl = $("display-url");
  const gaugeFill = $("gauge-fill");
  const scoreValue = $("score-value");
  const verdictSummaryTitle = $("verdict-summary-title");
  const verdictSummaryText = $("verdict-summary-text");
  const breakdownVisualChips = $("breakdown-visual-chips");
  const breakdownTableBody = $("breakdown-table-body");
  const findingsList = $("findings-list");
  const findingsCountBadge = $("findings-count-badge");
  const exampleButtons = document.querySelectorAll(".btn-chip");
  const historyList = $("history-list");
  const historyEmpty = $("history-empty");
  const clearHistoryBtn = $("clear-history-btn");
  const themeToggle = $("theme-toggle");

  const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 68; // ~427
  const HISTORY_KEY = "ziva_history";
  const THEME_KEY = "ziva_theme";
  const HISTORY_MAX = 10;

  /* ---------- helpers (all text goes through textContent: no XSS) ---------- */
  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function verdictClass(verdict) {
    return verdict === "Safe" ? "safe" : verdict === "Suspicious" ? "suspicious" : "danger";
  }

  function showError(msg) {
    inputError.textContent = msg;
    inputError.classList.remove("hidden");
    liveRegion.textContent = msg;
  }

  function clearError() {
    inputError.textContent = "";
    inputError.classList.add("hidden");
  }

  function setLoading(isLoading) {
    analyzeBtn.disabled = isLoading;
    btnLoader.classList.toggle("hidden", !isLoading);
    btnText.textContent = isLoading ? "Analyzing…" : "Analyze URL";
  }

  /* ---------- theme ---------- */
  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
  }
  try {
    applyTheme(localStorage.getItem(THEME_KEY) || "dark");
  } catch (e) {
    applyTheme("dark");
  }
  themeToggle.addEventListener("click", () => {
    const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
    applyTheme(next);
    try { localStorage.setItem(THEME_KEY, next); } catch (e) { /* ignore */ }
  });

  /* ---------- history (last 10, localStorage) ---------- */
  function loadHistory() {
    try {
      const raw = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
      return Array.isArray(raw) ? raw : [];
    } catch (e) {
      return [];
    }
  }

  function saveHistory(items) {
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify(items)); } catch (e) { /* ignore */ }
  }

  function addHistory(url, verdict, score) {
    const items = loadHistory().filter((i) => i.url !== url);
    items.unshift({ url, verdict, score });
    saveHistory(items.slice(0, HISTORY_MAX));
    renderHistory();
  }

  function renderHistory() {
    const items = loadHistory();
    historyList.replaceChildren();
    historyEmpty.classList.toggle("hidden", items.length > 0);
    historyList.classList.toggle("hidden", items.length === 0);
    items.forEach((item) => {
      const row = el("button", "history-item");
      row.type = "button";
      row.appendChild(el("span", "", item.url));
      row.appendChild(el("span", "history-verdict v-" + verdictClass(item.verdict), item.verdict + " (" + item.score + ")"));
      row.addEventListener("click", () => {
        urlInput.value = item.url;
        syncClearBtn();
        runAnalysis(item.url, false);
      });
      historyList.appendChild(row);
    });
  }

  clearHistoryBtn.addEventListener("click", () => {
    saveHistory([]);
    renderHistory();
  });

  /* ---------- URL anatomy (colored chips) ---------- */
  function renderBreakdown(parsed) {
    breakdownVisualChips.replaceChildren();
    const hostname = parsed.hostname || "";
    const reg = parsed.registered_domain || "";
    const subs = parsed.subdomains || [];

    if (parsed.scheme && parsed.scheme !== "missing") {
      breakdownVisualChips.appendChild(el("span", "bchip bchip-scheme", parsed.scheme + "://"));
    } else {
      breakdownVisualChips.appendChild(el("span", "bchip bchip-scheme", "(no scheme)"));
    }
    if (subs.length) {
      breakdownVisualChips.appendChild(el("span", "bchip bchip-sub", subs.join(".") + "."));
    }
    const dot = reg.indexOf(".");
    if (dot > 0 && reg === hostname.slice(hostname.length - reg.length)) {
      breakdownVisualChips.appendChild(el("span", "bchip bchip-domain", reg.slice(0, dot)));
      breakdownVisualChips.appendChild(el("span", "bchip bchip-tld", reg.slice(dot)));
    } else {
      breakdownVisualChips.appendChild(el("span", "bchip bchip-domain", reg || hostname));
    }
    if (parsed.port) {
      breakdownVisualChips.appendChild(el("span", "bchip bchip-path", ":" + parsed.port));
    }
    breakdownVisualChips.appendChild(el("span", "bchip bchip-path", parsed.path || "/"));

    breakdownTableBody.replaceChildren();
    const rows = [
      ["Scheme", parsed.scheme, "Protocol layer. Only https:// encrypts traffic."],
      ["Subdomains", subs.join(".") || "(none)", "Attackers stack these to show a trusted name first."],
      ["Registered Domain", reg, "The real owner of the site. This is what matters."],
      ["Port", parsed.port ? String(parsed.port) : "(default)", "Unusual ports are a mild red flag."],
      ["Path", parsed.path, "Target page on the server."],
    ];
    rows.forEach(([label, value, desc]) => {
      const tr = document.createElement("tr");
      const td1 = document.createElement("td");
      td1.appendChild(el("strong", "", label));
      const td2 = document.createElement("td");
      td2.appendChild(el("code", "", value));
      tr.appendChild(td1);
      tr.appendChild(td2);
      tr.appendChild(el("td", "", desc));
      breakdownTableBody.appendChild(tr);
    });
  }

  /* ---------- main analysis ---------- */
  async function runAnalysis(url, saveToHistory = true) {
    url = (url || "").trim();
    if (!url) return;
    clearError();
    setLoading(true);
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      let data = {};
      try { data = await res.json(); } catch (e) { /* non-JSON error */ }

      if (!res.ok) {
        let msg = "Error analyzing URL.";
        if (typeof data.detail === "string") msg = data.detail;
        else if (Array.isArray(data.detail) && data.detail[0] && data.detail[0].msg) msg = data.detail[0].msg;
        showError(msg);
        return;
      }

      displayUrl.textContent = data.defanged_url;
      verdictBadge.textContent = data.verdict.toUpperCase();
      verdictBadge.className = "verdict-badge verdict-" + verdictClass(data.verdict);

      scoreValue.textContent = data.score;
      const offset = GAUGE_CIRCUMFERENCE - (data.score / 100) * GAUGE_CIRCUMFERENCE;
      gaugeFill.style.strokeDashoffset = offset;
      gaugeFill.style.stroke =
        data.verdict === "Safe" ? "#10b981" : data.verdict === "Suspicious" ? "#f59e0b" : "#ef4444";

      verdictSummaryTitle.textContent = data.verdict + " (Score " + data.score + "/100)";
      verdictSummaryText.textContent =
        data.verdict === "Safe"
          ? "No red flags identified. URL conforms to safe patterns."
          : data.verdict === "Suspicious"
          ? "Potential phishing red flags detected. Proceed with caution."
          : "Severe phishing indicators detected. Do not click or submit data.";

      renderBreakdown(data.parsed);

      findingsList.replaceChildren();
      findingsCountBadge.textContent = data.findings.length;
      if (data.findings.length === 0) {
        findingsList.appendChild(el("p", "", "No red flags found."));
      }
      data.findings.forEach((f) => {
        const sev = ["low", "medium", "high"].includes(f.severity) ? f.severity : "low";
        const div = el("div", "finding-item sev-" + sev);
        div.appendChild(el("h4", "", "[" + sev.toUpperCase() + "] " + f.title));
        div.appendChild(el("p", "", f.explanation));
        findingsList.appendChild(div);
      });

      resultsSection.classList.remove("hidden");
      liveRegion.textContent = "Result: " + data.verdict + ", score " + data.score + " out of 100.";
      resultsSection.scrollIntoView({ behavior: "smooth" });

      if (saveToHistory) addHistory(data.url, data.verdict, data.score);
    } catch (err) {
      showError("Failed to communicate with analyzer.");
    } finally {
      setLoading(false);
    }
  }

  /* ---------- events ---------- */
  function syncClearBtn() {
    clearInputBtn.classList.toggle("hidden", urlInput.value.length === 0);
  }
  urlInput.addEventListener("input", syncClearBtn);
  clearInputBtn.addEventListener("click", () => {
    urlInput.value = "";
    syncClearBtn();
    clearError();
    urlInput.focus();
  });

  analyzeForm.addEventListener("submit", (e) => {
    e.preventDefault();
    runAnalysis(urlInput.value);
  });

  exampleButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const url = btn.getAttribute("data-url");
      urlInput.value = url;
      syncClearBtn();
      runAnalysis(url);
    });
  });

  renderHistory();
})();
