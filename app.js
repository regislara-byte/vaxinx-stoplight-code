const REPORT_PATH = "reports/scan_report.json";

const $ = (id) => document.getElementById(id);

function setText(id, value) {
  const el = $(id);
  if (el) el.textContent = value;
}

function badge(decision) {
  const color =
    decision === "RED" ? "badge-red" :
    decision === "YELLOW" ? "badge-yellow" :
    "badge-green";

  return `<span class="badge ${color}"><span class="dot"></span>${decision}</span>`;
}

function renderReport(report) {
  const summary = report.summary || {};

  setText("totalFiles", summary.total_files ?? 0);
  setText("greenCount", summary.green ?? 0);
  setText("yellowCount", summary.yellow ?? 0);
  setText("redCount", summary.red ?? 0);
  setText("quarantineCount", summary.quarantined ?? 0);

  const alertBanner = $("alertBanner");

  if ((summary.red ?? 0) > 0) {
    alertBanner.classList.remove("hidden");
    alertBanner.setAttribute("aria-hidden", "false");
  } else {
    alertBanner.classList.add("hidden");
    alertBanner.setAttribute("aria-hidden", "true");
  }

  const tbody = $("reportBody");
  tbody.innerHTML = "";

  const results = report.results || [];

  if (!results.length) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align:center;padding:32px;">
          // NO FILE RESULTS FOUND
        </td>
      </tr>
    `;
    return;
  }

  results.forEach((item) => {
    const quarantine = item.quarantine || {};
    const reasons = (item.reasons || []).slice(0, 3).join(" | ");
    const hints = (item.malware_hints || []).slice(0, 2).join(" | ");

    const qStatus =
      quarantine.status === "QUARANTINED"
        ? `🔐 VAULTED`
        : quarantine.status || "NOT_REQUIRED";

    const row = document.createElement("tr");

    row.innerHTML = `
      <td>${badge(item.stoplight)}</td>
      <td>${item.name}</td>
      <td>${item.file_type || "-"}</td>
      <td>${hints || "-"}</td>
      <td>${item.score ?? 0}</td>
      <td>${reasons || "-"}</td>
      <td>${qStatus}</td>
    `;

    tbody.appendChild(row);
  });

  $("statusText").innerHTML =
    `Loaded <code>${REPORT_PATH}</code> | Scanner: <code>${report.version}</code>`;
}

async function loadReport() {
  try {
    $("statusText").textContent = "Loading scan report...";

    const response = await fetch(REPORT_PATH, { cache: "no-store" });

    if (!response.ok) {
      throw new Error("Report not found. Run python scanner.py first.");
    }

    const report = await response.json();
    renderReport(report);
  } catch (error) {
    $("statusText").textContent = `ERROR: ${error.message}`;
  }
}

function simulateRedAlert() {
  $("alertBanner").classList.remove("hidden");
  $("alertBanner").setAttribute("aria-hidden", "false");
  $("statusText").textContent = "Simulated RED ALERT mode engaged.";
}

$("loadReportBtn")?.addEventListener("click", loadReport);
$("simulateAlertBtn")?.addEventListener("click", simulateRedAlert);

loadReport();