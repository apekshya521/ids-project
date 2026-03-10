/* ══════════════════════════════════════════
   IDS Dashboard — Main JavaScript
   ══════════════════════════════════════════ */

let allAlerts = [];
let lineChart = null;
let donutChart = null;
let barChart = null;
let attackChart = null;
let selectedAlertIdx = -1;

let lastTotalAlerts = 0;
const timeLabels = [];
const timeCounts = [];

// ── Page Navigation ─────────────────────
function navigateTo(pageId, linkEl) {
    // Hide all pages
    document.querySelectorAll('.page-section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.page-section').forEach(s => s.style.display = 'none');

    // Show target
    const target = document.getElementById('page-' + pageId);
    if (target) {
        target.classList.add('active');
        target.style.display = '';
    }

    // Update sidebar active
    document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
    if (linkEl) {
        linkEl.classList.add('active');
    }

    // If switching to alerts page, re-render full table
    if (pageId === 'alerts') renderFullTable();
}

// Initialize: hide non-active pages
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.page-section').forEach(s => {
        if (!s.classList.contains('active')) s.style.display = 'none';
    });
});

// ── WebSocket Setup ─────────────────────
const ws = new WebSocket(`ws://${location.host}/ws`);

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type === "NEW_ALERT") {
        console.log("New Live Alert:", data.alert);
        fetchAlerts();
    }
};

// ── Score color helper ──────────────────
function scoreColor(score) {
    if (score >= 80) return "#ef4444";
    if (score >= 60) return "#f97316";
    if (score >= 40) return "#eab308";
    return "#22c55e";
}

// ── Render Dashboard Alert Table ────────
function renderTable() {
    const search = document.getElementById("search").value.toLowerCase();
    const severity = document.getElementById("filter-severity").value;
    const channel = document.getElementById("filter-channel").value;
    const tbody = document.getElementById("alert-body");

    const filtered = allAlerts.filter(a => {
        const matchSearch = !search ||
            (a.username || "").toLowerCase().includes(search) ||
            (a.ip_address || "").toLowerCase().includes(search) ||
            (a.reason || "").toLowerCase().includes(search) ||
            (a.description || "").toLowerCase().includes(search) ||
            String(a.event_id).includes(search);
        const matchSev = !severity || a.severity === severity;
        const matchChan = !channel || a.channel === channel;
        return matchSearch && matchSev && matchChan;
    });

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr><td colspan="9">
                <div class="empty">
                    <span class="icon">🔍</span>
                    No alerts found
                </div>
            </td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map((a, i) => `
        <tr class="${a.severity} ${selectedAlertIdx === allAlerts.indexOf(a) ? 'selected' : ''}"
            onclick="selectAlert(${allAlerts.indexOf(a)})">
            <td><b><a href="#" onclick="showEventDetails(${allAlerts.indexOf(a)}, event); return false;" class="event-id-link">${a.event_id}</a></b></td>
            <td><span class="badge ${a.severity}">${a.severity}</span></td>
            <td>
                <div class="score-wrap">
                    <b>${a.risk_score}</b>
                    <div class="score-bar">
                        <div class="score-fill"
                             style="width:${a.risk_score}%;
                                    background:${scoreColor(a.risk_score)}">
                        </div>
                    </div>
                </div>
            </td>
            <td>${a.username || "—"}</td>
            <td>${a.ip_address || "local"}</td>
            <td>${a.channel || "—"}</td>
            <td>${a.source || "—"}</td>
            <td>${a.time || "—"}</td>
            <td title="${a.mitigation || ''}">${a.reason || a.description || "—"}</td>
        </tr>`
    ).join("");
}

// ── Render Full Alerts Table (Alerts page) ──
function renderFullTable() {
    const search = document.getElementById("search").value.toLowerCase();
    const severity = document.getElementById("filter-severity").value;
    const channel = document.getElementById("filter-channel").value;
    const tbody = document.getElementById("alert-body-full");

    if (!tbody) return;

    const filtered = allAlerts.filter(a => {
        const matchSearch = !search ||
            (a.username || "").toLowerCase().includes(search) ||
            (a.ip_address || "").toLowerCase().includes(search) ||
            (a.reason || "").toLowerCase().includes(search) ||
            (a.description || "").toLowerCase().includes(search) ||
            String(a.event_id).includes(search);
        const matchSev = !severity || a.severity === severity;
        const matchChan = !channel || a.channel === channel;
        return matchSearch && matchSev && matchChan;
    });

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr><td colspan="10">
                <div class="empty">
                    <span class="icon">🔍</span>
                    No alerts found
                </div>
            </td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(a => `
        <tr class="${a.severity}"
            onclick="selectAlert(${allAlerts.indexOf(a)})">
            <td><b><a href="#" onclick="showEventDetails(${allAlerts.indexOf(a)}, event); return false;" class="event-id-link">${a.event_id}</a></b></td>
            <td><span class="badge ${a.severity}">${a.severity}</span></td>
            <td>
                <div class="score-wrap">
                    <b>${a.risk_score}</b>
                    <div class="score-bar">
                        <div class="score-fill"
                             style="width:${a.risk_score}%;
                                    background:${scoreColor(a.risk_score)}">
                        </div>
                    </div>
                </div>
            </td>
            <td>${a.reason || "—"}</td>
            <td>${a.username || "—"}</td>
            <td>${a.ip_address || "local"}</td>
            <td>${a.channel || "—"}</td>
            <td>${a.source || "—"}</td>
            <td>${a.computer || "—"}</td>
            <td>${a.time || "—"}</td>
        </tr>`
    ).join("");
}

// ── Select Alert → Investigation Panel ──
function selectAlert(idx) {
    selectedAlertIdx = idx;
    const a = allAlerts[idx];
    if (!a) return;

    document.getElementById("inv-empty").style.display = "none";
    const content = document.getElementById("inv-content");
    content.style.display = "flex";
    content.style.flexDirection = "column";
    content.style.flex = "1";

    // Parse mitigations (may be comma-separated or newline-separated)
    let mitigations = [];
    if (a.mitigation) {
        mitigations = a.mitigation.split(/[,\n]/).map(s => s.trim()).filter(Boolean);
    }
    if (mitigations.length === 0) {
        mitigations = ["Monitor and review this event", "Check system logs for context"];
    }

    content.innerHTML = `
        <div class="inv-header">
            <div>
                <span class="event-label">Event ID:</span>
                <span class="event-id-val">${a.event_id}</span>
            </div>
            <span class="badge ${a.severity}">${a.severity}</span>
        </div>

        <div class="risk-gauge-wrap">
            <div class="risk-gauge">
                <canvas id="gaugeCanvas" width="100" height="100"></canvas>
                <div class="gauge-text" style="color:${scoreColor(a.risk_score)}">${a.risk_score}</div>
                <div class="gauge-label">/100</div>
            </div>
        </div>

        <div class="inv-info">
            <div class="inv-info-row">
                <span class="inv-icon">👤</span>
                <span class="inv-label">User:</span>
                <span class="inv-value">${a.username || "—"}</span>
            </div>
            <div class="inv-info-row">
                <span class="inv-icon">💻</span>
                <span class="inv-label">Computer:</span>
                <span class="inv-value">${a.computer || "—"}</span>
            </div>
            <div class="inv-info-row">
                <span class="inv-icon">🌐</span>
                <span class="inv-label">IP Address:</span>
                <span class="inv-value">${a.ip_address || "local"}</span>
            </div>
            <div class="inv-info-row">
                <span class="inv-icon">📁</span>
                <span class="inv-label">Channel:</span>
                <span class="inv-value">${a.channel || "—"}</span>
            </div>
            <div class="inv-info-row">
                <span class="inv-icon">�</span>
                <span class="inv-label">Source:</span>
                <span class="inv-value">${a.source || "—"}</span>
            </div>
            <div class="inv-info-row">
                <span class="inv-icon">�🕐</span>
                <span class="inv-label">Time:</span>
                <span class="inv-value">${a.time || "—"}</span>
            </div>
        </div>

        <div class="inv-section">
            <div class="inv-section-title">Attack Type</div>
            <p style="font-size:13px;color:var(--text-primary);">${a.reason || a.description || "—"}</p>
        </div>

        <div class="inv-section">
            <div class="inv-section-title">Recommended Mitigation</div>
            <ul class="inv-mitigations">
                ${mitigations.map(m => `<li>✓ ${m}</li>`).join("")}
            </ul>
        </div>

        <div class="inv-section">
            <div class="inv-section-title">Event Viewer Details (Raw Data)</div>
            <div class="inv-raw-data">
                ${renderRawData(a.raw_data)}
            </div>
        </div>

        <button class="btn-investigated" onclick="markInvestigated()">
            ✅ Alert Investigated
        </button>
    `;

    // Draw risk gauge
    drawGauge(a.risk_score);

    // Highlight selected row
    renderTable();
}

// Helper to format raw JSON string inserts into a readable list
function renderRawData(rawStr) {
    if (!rawStr || rawStr === "[]") return "<span class='no-raw'>No raw string inserts available.</span>";
    try {
        const data = JSON.parse(rawStr);
        if (Array.isArray(data) && data.length > 0) {
            return `<ul class="raw-data-list">` + 
                   data.map((d, i) => `<li><span class="raw-idx">[${i}]</span> ${escapeHtml(d)}</li>`).join("") +
                   `</ul>`;
        }
    } catch(e) {
        return `<pre class="raw-data-text">${escapeHtml(rawStr)}</pre>`;
    }
    return "<span class='no-raw'>No raw string inserts available.</span>";
}

// Utility to escape HTML to prevent XSS
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return String(unsafe);
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

// ── Draw Risk Score Gauge ────────────────
function drawGauge(score) {
    const canvas = document.getElementById("gaugeCanvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const cx = 50, cy = 50, r = 38;

    ctx.clearRect(0, 0, 100, 100);

    // Background arc
    ctx.beginPath();
    ctx.arc(cx, cy, r, Math.PI * 0.75, Math.PI * 2.25, false);
    ctx.lineWidth = 8;
    ctx.strokeStyle = "#1e2d45";
    ctx.lineCap = "round";
    ctx.stroke();

    // Score arc
    const range = Math.PI * 1.5; // total arc range
    const endAngle = Math.PI * 0.75 + (score / 100) * range;
    ctx.beginPath();
    ctx.arc(cx, cy, r, Math.PI * 0.75, endAngle, false);
    ctx.lineWidth = 8;
    ctx.strokeStyle = scoreColor(score);
    ctx.lineCap = "round";
    ctx.stroke();
}

// ── Event Details Modal ───────────────────
function showEventDetails(idx, event) {
    event.stopPropagation(); // Prevent row click
    const a = allAlerts[idx];
    if (!a) return;

    // Use existing investigation panel as overlay
    selectedAlertIdx = idx;
    
    // Determine which investigation panel to use based on active page
    const alertsPage = document.getElementById('page-alerts');
    const isAlertsPage = alertsPage && alertsPage.style.display !== 'none';
    
    const panelId = isAlertsPage ? 'investigation-panel-alerts' : 'investigation-panel';
    const emptyId = isAlertsPage ? 'inv-empty-alerts' : 'inv-empty';
    const contentId = isAlertsPage ? 'inv-content-alerts' : 'inv-content';
    
    // Show investigation panel as overlay
    const panel = document.getElementById(panelId);
    panel.style.display = "flex";
    
    document.getElementById(emptyId).style.display = "none";
    const content = document.getElementById(contentId);
    content.style.display = "flex";
    content.style.flexDirection = "column";
    content.style.flex = "1";

    // Parse mitigations
    let mitigations = [];
    if (a.mitigation) {
        mitigations = a.mitigation.split(/[,\n]/).map(s => s.trim()).filter(Boolean);
    }
    if (mitigations.length === 0) {
        mitigations = ["Monitor and review this event", "Check system logs for context"];
    }

    content.innerHTML = `
        <div class="inv-header">
            <div>
                <span class="event-label">Event ID:</span>
                <span class="event-id-val">${a.event_id}</span>
            </div>
            <span class="badge ${a.severity}">${a.severity}</span>
        </div>

        <div class="risk-gauge-wrap">
            <div class="risk-gauge">
                <canvas id="gaugeCanvas" width="100" height="100"></canvas>
                <div class="gauge-text" style="color:${scoreColor(a.risk_score)}">${a.risk_score}</div>
                <div class="gauge-label">/100</div>
            </div>
        </div>

        <div class="inv-info">
            <div class="inv-info-row">
                <span class="inv-icon">👤</span>
                <span class="inv-label">Username:</span>
                <span class="inv-value">${a.username || "—"}</span>
            </div>
            <div class="inv-info-row">
                <span class="inv-icon">💻</span>
                <span class="inv-label">Computer:</span>
                <span class="inv-value">${a.computer || "—"}</span>
            </div>
            <div class="inv-info-row">
                <span class="inv-icon">🌐</span>
                <span class="inv-label">IP Address:</span>
                <span class="inv-value">${a.ip_address || "local"}</span>
            </div>
            <div class="inv-info-row">
                <span class="inv-icon">📁</span>
                <span class="inv-label">Channel:</span>
                <span class="inv-value">${a.channel || "—"}</span>
            </div>
            <div class="inv-info-row">
                <span class="inv-icon">🔧</span>
                <span class="inv-label">Source:</span>
                <span class="inv-value">${a.source || "—"}</span>
            </div>
            <div class="inv-info-row">
                <span class="inv-icon">🕐</span>
                <span class="inv-label">Time:</span>
                <span class="inv-value">${a.time || "—"}</span>
            </div>
            <div class="inv-info-row">
                <span class="inv-icon">📝</span>
                <span class="inv-label">Event Description:</span>
                <span class="inv-value">${a.description || "—"}</span>
            </div>
        </div>
    `;

    // Draw risk gauge
    drawGauge(a.risk_score);

    // Highlight selected row
    renderTable();
}

function closeInvestigationPanel() {
    // Hide both investigation panels
    const dashboardPanel = document.getElementById("investigation-panel");
    const alertsPanel = document.getElementById("investigation-panel-alerts");
    
    if (dashboardPanel) dashboardPanel.style.display = "none";
    if (alertsPanel) alertsPanel.style.display = "none";
    
    selectedAlertIdx = -1;
    renderTable();
}

function closeEventModal() {
    document.getElementById("eventModal").style.display = "none";
}

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById("eventModal");
    if (event.target == modal) {
        closeEventModal();
    }
}

// ── Mark alert as investigated ──────────
function markInvestigated() {
    if (selectedAlertIdx >= 0) {
        // Visual feedback
        selectedAlertIdx = -1;
        document.getElementById("inv-empty").style.display = "";
        document.getElementById("inv-content").style.display = "none";
        renderTable();
    }
}



// ── Donut Chart ─────────────────────────
function updateDonut(stats) {
    const ctx = document.getElementById("donutChart").getContext("2d");
    const data = [stats.critical, stats.high, stats.medium, stats.low];

    if (donutChart) {
        donutChart.data.datasets[0].data = data;
        donutChart.update();
        return;
    }
    donutChart = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels: ["Critical", "High", "Medium", "Low"],
            datasets: [{
                data,
                backgroundColor: ["#ef4444", "#f97316", "#eab308", "#22c55e"],
                borderWidth: 0,
                hoverOffset: 6
            }]
        },
        options: {
            plugins: {
                legend: {
                    position: "right",
                    labels: {
                        color: "#8899aa", font: { size: 12 }, padding: 12,
                        usePointStyle: true, pointStyle: "circle"
                    }
                }
            },
            cutout: "65%",
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

// ── Line Chart ──────────────────────────
function updateLine(totalNow) {
    const ctx = document.getElementById("lineChart").getContext("2d");
    const time = new Date().toLocaleTimeString();

    let newAlerts = totalNow - lastTotalAlerts;
    if (lastTotalAlerts === 0 || newAlerts < 0) newAlerts = 0;
    lastTotalAlerts = totalNow;

    if (timeLabels.length >= 10) { timeLabels.shift(); timeCounts.shift(); }
    timeLabels.push(time);
    timeCounts.push(newAlerts);

    if (lineChart) {
        lineChart.data.labels = [...timeLabels];
        lineChart.data.datasets[0].data = [...timeCounts];
        lineChart.update();
        return;
    }
    lineChart = new Chart(ctx, {
        type: "line",
        data: {
            labels: [...timeLabels],
            datasets: [{
                label: "New Alerts",
                data: [...timeCounts],
                borderColor: "#3b82f6",
                backgroundColor: "rgba(59,130,246,0.08)",
                fill: true,
                tension: 0.4,
                pointRadius: 4,
                pointBackgroundColor: "#3b82f6"
            }]
        },
        options: {
            scales: {
                x: { ticks: { color: "#5a6a7a", maxTicksLimit: 5 }, grid: { color: "#1e2d45" } },
                y: { ticks: { color: "#5a6a7a" }, grid: { color: "#1e2d45" }, beginAtZero: true }
            },
            plugins: { legend: { display: false } },
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

// ── Top Targeted Users ──────────────────
function updateTopUsers(alerts) {
    const container = document.getElementById("top-users");
    if (!container) return;

    const userCount = {};
    alerts.forEach(a => {
        const u = a.username || "unknown";
        if (u !== "unknown" && u !== "—" && u !== "N/A") userCount[u] = (userCount[u] || 0) + 1;
    });

    const sorted = Object.entries(userCount)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);

    const maxCount = sorted.length ? sorted[0][1] : 1;

    container.innerHTML = sorted.map(([name, count]) => `
        <li>
            <span class="user-name">${name}</span>
            <div class="user-bar-wrap">
                <div class="user-bar" style="width:${(count / maxCount) * 100}%"></div>
            </div>
            <span class="user-count">${count}</span>
        </li>`
    ).join("") || '<li style="color:var(--text-muted);font-size:13px;">No data yet</li>';
}

// ── Attack Types Chart ──────────────────
function updateAttackTypes(alerts) {
    const ctx = document.getElementById("attackTypesChart");
    if (!ctx) return;

    // Categorize alerts by reason keywords
    const categories = {};
    alerts.forEach(a => {
        const reason = (a.reason || a.description || "Other").toLowerCase();
        let category = "Other";

        if (reason.includes("brute") || reason.includes("login fail")) category = "Brute Force";
        else if (reason.includes("privilege") || reason.includes("escalat")) category = "Privilege Escalation";
        else if (reason.includes("credential") || reason.includes("logon")) category = "Credential Access";
        else if (reason.includes("recon") || reason.includes("scan")) category = "Reconnaissance";
        else if (reason.includes("malware") || reason.includes("virus")) category = "Malware";
        else if (reason.includes("policy") || reason.includes("audit")) category = "Policy Violation";
        else if (reason.includes("service") || reason.includes("install")) category = "Service Change";

        categories[category] = (categories[category] || 0) + 1;
    });

    const sorted = Object.entries(categories).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const labels = sorted.map(e => e[0]);
    const data = sorted.map(e => e[1]);

    const colors = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#3b82f6", "#8b5cf6"];

    if (attackChart) {
        attackChart.data.labels = labels;
        attackChart.data.datasets[0].data = data;
        attackChart.data.datasets[0].backgroundColor = colors.slice(0, data.length);
        attackChart.update();
        return;
    }

    attackChart = new Chart(ctx.getContext("2d"), {
        type: "bar",
        data: {
            labels,
            datasets: [{
                label: "Count",
                data,
                backgroundColor: colors.slice(0, data.length),
                borderRadius: 4,
                barPercentage: 0.6
            }]
        },
        options: {
            indexAxis: "y",
            scales: {
                x: { ticks: { color: "#5a6a7a" }, grid: { color: "#1e2d45" }, beginAtZero: true },
                y: { ticks: { color: "#8899aa", font: { size: 11 } }, grid: { display: false } }
            },
            plugins: { legend: { display: false } },
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

// ── Fetch & Refresh ─────────────────────
async function fetchAlerts() {
    try {
        const [alertRes, statsRes] = await Promise.all([
            fetch("/api/alerts"),
            fetch("/api/stats")
        ]);

        allAlerts = await alertRes.json();
        const stats = await statsRes.json();

        // Stats bar
        document.getElementById("stat-total").textContent = stats.total || 0;
        document.getElementById("stat-critical").textContent = stats.critical || 0;
        document.getElementById("stat-high").textContent = stats.high || 0;
        document.getElementById("stat-medium").textContent = stats.medium || 0;
        document.getElementById("stat-low").textContent = stats.low || 0;

        // Charts
        updateDonut(stats);
        updateLine(stats.total || 0);
        updateTopUsers(allAlerts);
        updateAttackTypes(allAlerts);

        // Tables
        renderTable();
        renderFullTable();

        // Update host name from first alert if available
        if (allAlerts.length > 0 && allAlerts[0].computer) {
            document.getElementById("host-name").textContent = allAlerts[0].computer;
        } else {
            document.getElementById("host-name").textContent = "Local Host";
        }

        document.getElementById("last-updated").textContent =
            "Last Log Scan: " + new Date().toLocaleTimeString();

    } catch (err) {
        console.error("Fetch error:", err);
    }
}

// ── Clear Alerts ────────────────────────
async function clearAlerts() {
    await fetch("/api/alerts", { method: "DELETE" });
    allAlerts = [];
    timeLabels.length = 0;
    timeCounts.length = 0;
    lastTotalAlerts = 0;
    selectedAlertIdx = -1;
    document.getElementById("inv-empty").style.display = "";
    document.getElementById("inv-content").style.display = "none";
    renderTable();
    renderFullTable();
    fetchAlerts();
}

// ── Auto Refresh Every 10s ──────────────
fetchAlerts();
setInterval(fetchAlerts, 10000);