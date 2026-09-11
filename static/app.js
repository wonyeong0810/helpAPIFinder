const $ = (selector) => document.querySelector(selector);

const statusLabels = {
  new: "확인 필요",
  reviewing: "검토 중",
  notified: "알림 완료",
  resolved: "해결됨",
  false_positive: "오탐",
};

let searchTimer;
let toastTimer;
let lastRunning = false;

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-Keylight-Request": "dashboard",
      ...(options.headers || {}),
    },
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || "요청을 처리하지 못했습니다.");
  return payload;
}

function showToast(message, error = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.toggle("error", error);
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 3200);
}

function setText(selector, value) {
  $(selector).textContent = Number(value || 0).toLocaleString("ko-KR");
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "—";
  return new Intl.DateTimeFormat("ko-KR", {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  }).format(date);
}

function link(text, href, className) {
  const anchor = document.createElement("a");
  anchor.textContent = text;
  anchor.href = href;
  anchor.className = className;
  anchor.target = "_blank";
  anchor.rel = "noopener noreferrer";
  return anchor;
}

function renderSummary(summary) {
  setText("#metric-new", summary.new);
  setText("#metric-total", summary.total);
  setText("#metric-repositories", summary.repositories);
  setText("#metric-notified", summary.notified);

  const select = $("#provider-filter");
  const selected = select.value;
  const existing = new Set([...select.options].map((option) => option.value));
  for (const provider of summary.providers_supported || []) {
    if (!existing.has(provider)) {
      const option = document.createElement("option");
      option.value = provider;
      option.textContent = provider;
      select.append(option);
    }
  }
  select.value = selected;
}

function renderScan(payload) {
  const { scan, running } = payload;
  const badge = $("#scan-state");
  const button = $("#scan-button");
  lastRunning = running;
  button.disabled = running;
  badge.className = `scan-state ${running ? "running" : scan?.status === "failed" ? "failed" : "idle"}`;
  badge.textContent = running ? "검사 중" : scan?.status === "failed" ? "실패" : "대기 중";

  if (!scan) {
    $("#scan-summary").textContent = payload.schedule?.enabled
      ? "자동 검사가 준비되었습니다. 첫 검사를 시작하는 중입니다."
      : "아직 실행한 검사가 없습니다.";
    $("#scan-progress").textContent = payload.schedule?.enabled
      ? `자동 ${payload.schedule.interval_minutes}분`
      : "—";
    return;
  }
  if (scan.status === "failed") {
    $("#scan-summary").textContent = scan.error_message || "검사를 완료하지 못했습니다.";
  } else if (running) {
    $("#scan-summary").textContent = `후보 ${scan.repositories_discovered}개 중 ${scan.repositories_scanned}개 저장소 검사 완료`;
  } else {
    $("#scan-summary").textContent = `${formatDate(scan.finished_at)} · 신규 ${scan.findings_new}건 · 파일 ${scan.files_scanned}개 확인`;
  }
  $("#scan-progress").textContent = running
    ? `${scan.repositories_scanned} / ${scan.repositories_eligible || scan.repositories_discovered}`
    : payload.schedule?.enabled
      ? `자동 ${payload.schedule.interval_minutes}분`
      : scan.rate_remaining == null ? "완료" : `API ${scan.rate_remaining}회 남음`;
}

function makeCell() {
  return document.createElement("td");
}

function renderFinding(item) {
  const row = document.createElement("tr");

  const detected = makeCell();
  const provider = document.createElement("span");
  provider.className = "provider";
  const dot = document.createElement("span");
  dot.className = "provider-dot";
  provider.append(dot, document.createTextNode(item.provider));
  const mask = document.createElement("span");
  mask.className = "secret-mask";
  mask.textContent = item.masked_secret;
  detected.append(provider, mask);

  const repository = makeCell();
  repository.append(link(item.repository, item.repo_url, "repo-link"));
  const owner = link(`@${item.owner}`, item.owner_url, "owner-link");
  repository.append(owner);
  const beginner = document.createElement("span");
  beginner.className = "beginner-note";
  const signals = Array.isArray(item.beginner_signals) ? item.beginner_signals : [];
  beginner.textContent = `초보 추정 ${item.beginner_score || 0}점${signals.length ? ` · ${signals.slice(0, 2).join(" · ")}` : ""}`;
  beginner.title = signals.join(" · ");
  repository.append(beginner);

  const location = makeCell();
  location.append(link(item.file_path, item.file_url, "file-link"));
  const line = document.createElement("span");
  line.className = "line-meta";
  line.textContent = `line ${item.line_number} · ${item.confidence} confidence`;
  const evidence = document.createElement("code");
  evidence.className = "evidence";
  evidence.textContent = item.evidence || "[REDACTED]";
  location.append(line, evidence);

  const time = makeCell();
  const timeMain = document.createElement("span");
  timeMain.className = "time-main";
  timeMain.textContent = formatDate(item.last_seen_at);
  const seen = document.createElement("span");
  seen.className = "time-sub";
  seen.textContent = `${item.scan_count}회 탐지`;
  time.append(timeMain, seen);

  const statusCell = makeCell();
  const select = document.createElement("select");
  select.className = "status-select";
  select.setAttribute("aria-label", `${item.repository} 상태`);
  for (const [value, label] of Object.entries(statusLabels)) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    option.selected = item.status === value;
    select.append(option);
  }
  select.addEventListener("change", async () => {
    select.disabled = true;
    try {
      await api(`/api/findings/${item.id}`, {
        method: "PATCH",
        body: JSON.stringify({ status: select.value }),
      });
      showToast(`상태를 '${statusLabels[select.value]}'(으)로 변경했습니다.`);
      await loadSummary();
      if ($("#status-filter").value) await loadFindings();
    } catch (error) {
      select.value = item.status;
      showToast(error.message, true);
    } finally {
      select.disabled = false;
    }
  });
  statusCell.append(select);

  const action = makeCell();
  const open = link("↗", item.file_url, "open-link");
  open.title = "GitHub에서 파일 열기";
  open.setAttribute("aria-label", "GitHub에서 파일 열기");
  action.append(open);

  row.append(detected, repository, location, time, statusCell, action);
  return row;
}

async function loadSummary() {
  renderSummary(await api("/api/summary"));
}

async function loadFindings() {
  const params = new URLSearchParams();
  const search = $("#search-input").value.trim();
  const provider = $("#provider-filter").value;
  const status = $("#status-filter").value;
  if (search) params.set("q", search);
  if (provider) params.set("provider", provider);
  if (status) params.set("status", status);

  const result = await api(`/api/findings?${params}`);
  const body = $("#findings-body");
  body.replaceChildren(...result.items.map(renderFinding));
  $("#result-count").textContent = `${Number(result.total).toLocaleString("ko-KR")}건`;
  $("#empty-state").hidden = result.items.length > 0;
}

async function loadScan() {
  const wasRunning = lastRunning;
  const payload = await api("/api/scans/latest");
  renderScan(payload);
  if (wasRunning && !payload.running) {
    await Promise.all([loadSummary(), loadFindings()]);
    showToast(payload.scan?.status === "completed" ? "검사가 완료되었습니다." : "검사를 완료하지 못했습니다.", payload.scan?.status !== "completed");
  }
}

async function loadAll() {
  try {
    await Promise.all([loadSummary(), loadFindings(), loadScan()]);
  } catch (error) {
    showToast(error.message, true);
  }
}

$("#scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("#scan-button");
  button.disabled = true;
  try {
    await api("/api/scans", {
      method: "POST",
      body: JSON.stringify({
        recent_days: $("#recent-days").value,
        max_repositories: $("#max-repositories").value,
      }),
    });
    showToast("검사를 시작했습니다. 화면은 자동으로 갱신됩니다.");
    await loadScan();
  } catch (error) {
    showToast(error.message, true);
    button.disabled = false;
  }
});

$("#refresh-button").addEventListener("click", loadAll);
$("#provider-filter").addEventListener("change", loadFindings);
$("#status-filter").addEventListener("change", loadFindings);
$("#search-input").addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(loadFindings, 250);
});

loadAll();
setInterval(() => loadScan().catch(() => {}), 3500);
