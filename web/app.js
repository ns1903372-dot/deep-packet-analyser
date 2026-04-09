const pcapInput = document.getElementById("pcap");
const sampleSelect = document.getElementById("sampleSelect");
const blockAppInput = document.getElementById("blockApp");
const blockDomainInput = document.getElementById("blockDomain");
const blockIpInput = document.getElementById("blockIp");
const runBtn = document.getElementById("runBtn");
const statusEl = document.getElementById("status");
const errorEl = document.getElementById("error");
const reportEl = document.getElementById("report");
const actionsEl = document.getElementById("actions");
const chartEl = document.getElementById("chart");
const threadTableEl = document.getElementById("threadTable");
const domainTableEl = document.getElementById("domainTable");

const statsEls = {
  totalPackets: document.getElementById("statPackets"),
  forwarded: document.getElementById("statForwarded"),
  dropped: document.getElementById("statDropped"),
  activeFlows: document.getElementById("statFlows")
};

boot();

async function boot() {
  await loadSamples();
  await checkBackend();
}

async function loadSamples() {
  try {
    const response = await fetch("/api/examples");
    const payload = await response.json();
    (payload.samples || []).forEach(sample => {
      const option = document.createElement("option");
      option.value = sample.id;
      option.textContent = sample.label;
      sampleSelect.appendChild(option);
    });
  } catch {
    statusEl.textContent = "Could not load sample catalog.";
  }
}

async function checkBackend() {
  try {
    const response = await fetch("/api/health");
    const payload = await response.json();
    if (payload.status === "ok") {
      statusEl.textContent = "Backend is ready.";
    }
  } catch {
    statusEl.textContent = "Backend health check failed.";
  }
}

runBtn.addEventListener("click", async () => {
  errorEl.textContent = "";
  actionsEl.innerHTML = "";
  reportEl.textContent = "Running analysis...";
  setStats({ totalPackets: "-", forwarded: "-", dropped: "-", activeFlows: "-" });
  renderChart([]);
  renderThreadTable([]);
  renderDomainTable([]);

  const file = pcapInput.files[0];
  const sampleId = sampleSelect.value;

  if (!file && !sampleId) {
    reportEl.textContent = "Run an analysis to see the backend output.";
    errorEl.textContent = "Upload a PCAP file or choose a bundled sample.";
    return;
  }

  try {
    const payload = {
      filename: file ? file.name : "",
      data: file ? await fileToBase64(file) : "",
      sampleId,
      blockApp: blockAppInput.value,
      blockDomain: blockDomainInput.value,
      blockIp: blockIpInput.value
    };

    statusEl.textContent = "Analyzing packets with the Java backend...";
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const result = await response.json();
    if (!response.ok) {
      throw new Error(result.error || "Analysis failed");
    }

    reportEl.textContent = result.report || "No report generated.";
    setStats(result.stats || {});
    renderChart(result.appBreakdown || []);
    renderThreadTable(result.threadStats || []);
    renderDomainTable(result.detectedDomains || []);
    statusEl.textContent = "Analysis complete.";

    if (result.downloadPath) {
      const link = document.createElement("a");
      link.className = "action-link";
      link.href = result.downloadPath;
      link.textContent = "Download filtered PCAP";
      actionsEl.appendChild(link);
    }
  } catch (error) {
    reportEl.textContent = "Run an analysis to see the backend output.";
    errorEl.textContent = error.message || String(error);
    statusEl.textContent = "Analysis failed.";
  }
});

function setStats(stats) {
  statsEls.totalPackets.textContent = stats.totalPackets ?? "-";
  statsEls.forwarded.textContent = stats.forwarded ?? "-";
  statsEls.dropped.textContent = stats.dropped ?? "-";
  statsEls.activeFlows.textContent = stats.activeFlows ?? "-";
}

function renderChart(rows) {
  chartEl.innerHTML = "";
  if (!rows.length) {
    chartEl.innerHTML = '<div class="muted">No application data yet.</div>';
    return;
  }

  const maxValue = Math.max(...rows.map(row => row.value), 1);
  rows
    .sort((left, right) => right.value - left.value)
    .slice(0, 10)
    .forEach(row => {
      const item = document.createElement("div");
      item.className = "chart-row";
      item.innerHTML = `
        <div class="chart-label">${escapeHtml(row.name)}</div>
        <div class="chart-bar"><div class="chart-fill" style="width:${(row.value / maxValue) * 100}%"></div></div>
        <div class="chart-value">${row.value}</div>
      `;
      chartEl.appendChild(item);
    });
}

function renderThreadTable(rows) {
  threadTableEl.innerHTML = "";
  if (!rows.length) {
    threadTableEl.innerHTML = '<tr><td colspan="5">No thread data yet.</td></tr>';
    return;
  }

  rows.forEach(row => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(row.name)}</td>
      <td>${row.dispatched ?? 0}</td>
      <td>${row.processed ?? 0}</td>
      <td>${row.forwarded ?? 0}</td>
      <td>${row.dropped ?? 0}</td>
    `;
    threadTableEl.appendChild(tr);
  });
}

function renderDomainTable(domains) {
  domainTableEl.innerHTML = "";
  if (!domains.length) {
    domainTableEl.innerHTML = '<tr><td colspan="2">No detected domains yet.</td></tr>';
    return;
  }

  domains.forEach((domain, index) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${index + 1}</td>
      <td>${escapeHtml(domain)}</td>
    `;
    domainTableEl.appendChild(tr);
  });
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",")[1]);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
