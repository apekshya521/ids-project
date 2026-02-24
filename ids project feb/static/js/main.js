let allAlerts  = [];
let lineChart  = null;
let donutChart = null;
let barChart   = null;

let lastTotalAlerts = 0; // Track last count for line chart deltas
const timeLabels = [];
const timeCounts = [];

// ── WebSocket Setup ──────────────────────
const ws = new WebSocket(`ws://${location.host}/ws`);

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type === "NEW_ALERT") {
        console.log("New Live Alert:", data.alert);
        fetchAlerts(); // Refresh all data when live alert hits
    }
};

// ── Score bar color ──────────────────────
function scoreColor(score) {
    if (score >= 80) return "#f85149";
    if (score >= 60) return "#ff7b35";
    if (score >= 40) return "#e3b341";
    return "#3fb950";
}

// ── Render Alert Table ───────────────────
function renderTable() {
    const search   = document.getElementById("search").value.toLowerCase();
    const severity = document.getElementById("filter-severity").value;
    const channel  = document.getElementById("filter-channel").value;
    const tbody    = document.getElementById("alert-body");

    const filtered = allAlerts.filter(a => {
        const matchSearch = !search ||
            (a.username   || "").toLowerCase().includes(search) ||
            (a.ip_address || "").toLowerCase().includes(search) ||
            (a.reason     || "").toLowerCase().includes(search) ||
            String(a.event_id).includes(search);
        const matchSev  = !severity || a.severity === severity;
        const matchChan = !channel  || a.channel  === channel;
        return matchSearch && matchSev && matchChan;
    });

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr><td colspan="9">
                <div class="empty">
                    No alerts found
                </div>
            </td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(a => `
        <tr class="${a.severity}">
            <td><b>${a.event_id}</b></td>
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
            <td title="${a.mitigation}">${a.reason}</td>
            <td>${a.username   || "—"}</td>
            <td>${a.ip_address || "local"}</td>
            <td>${a.channel    || "—"}</td>
            <td>${a.computer   || "—"}</td>
            <td>${a.time       || "—"}</td>
        </tr>`
    ).join("");
}

// ── Donut Chart ──────────────────────────
function updateDonut(stats) {
    const ctx  = document.getElementById("donutChart").getContext("2d");
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
                backgroundColor: ["#f85149","#ff7b35","#e3b341","#3fb950"],
                borderWidth: 0,
                hoverOffset: 6
            }]
        },
        options: {
            plugins: {
                legend: {
                    labels: { color: "#8b949e", font: { size: 12 } }
                }
            },
            cutout: "65%"
        }
    });
}

// ── Line Chart ───────────────────────────
function updateLine(totalNow) {
    const ctx  = document.getElementById("lineChart").getContext("2d");
    const time = new Date().toLocaleTimeString();

    // Calculate new alerts (delta) since last poll/update
    let newAlerts = totalNow - lastTotalAlerts;
    if (lastTotalAlerts === 0 || newAlerts < 0) {
        newAlerts = 0; // First load or clear
    }
    lastTotalAlerts = totalNow;

    // Keep last 10 data points
    if (timeLabels.length >= 10) {
        timeLabels.shift();
        timeCounts.shift();
    }
    timeLabels.push(time);
    timeCounts.push(newAlerts);

    if (lineChart) {
        lineChart.data.labels                 = [...timeLabels];
        lineChart.data.datasets[0].data       = [...timeCounts];
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
                borderColor: "#58a6ff",
                backgroundColor: "rgba(88,166,255,0.1)",
                fill: true,
                tension: 0.4,
                pointRadius: 4,
                pointBackgroundColor: "#58a6ff"
            }]
        },
        options: {
            scales: {
                x: { ticks: { color: "#8b949e", maxTicksLimit: 5 }, grid: { color: "#21262d" }},
                y: { ticks: { color: "#8b949e" }, grid: { color: "#21262d" }, beginAtZero: true }
            },
            plugins: { legend: { display: false }}
        }
    });
}

// ── Bar Chart (Top Users) ────────────────
function updateBar(alerts) {
    const ctx      = document.getElementById("barChart").getContext("2d");
    const userCount = {};

    alerts.forEach(a => {
        const u = a.username || "unknown";
        if (u !== "unknown") userCount[u] = (userCount[u] || 0) + 1;
    });

    // Top 6 users
    const sorted = Object.entries(userCount)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 6);

    const labels = sorted.map(e => e[0]);
    const data   = sorted.map(e => e[1]);

    if (barChart) {
        barChart.data.labels             = labels;
        barChart.data.datasets[0].data   = data;
        barChart.update();
        return;
    }
    barChart = new Chart(ctx, {
        type: "bar",
        data: {
            labels,
            datasets: [{
                label: "Alert Count",
                data,
                backgroundColor: "#f85149",
                borderRadius: 4
            }]
        },
        options: {
            scales: {
                x: { ticks: { color: "#8b949e" }, grid: { color: "#21262d" }},
                y: { ticks: { color: "#8b949e" }, grid: { color: "#21262d" }, beginAtZero: true }
            },
            plugins: { legend: { display: false }}
        }
    });
}

// ── Fetch & Refresh ──────────────────────
async function fetchAlerts() {
    try {
        const [alertRes, statsRes] = await Promise.all([
            fetch("/api/alerts"),
            fetch("/api/stats")
        ]);

        allAlerts   = await alertRes.json();
        const stats = await statsRes.json();

        // Stats bar
        document.getElementById("stat-total").textContent    = stats.total    || 0;
        document.getElementById("stat-critical").textContent = stats.critical || 0;
        document.getElementById("stat-high").textContent     = stats.high     || 0;
        document.getElementById("stat-medium").textContent   = stats.medium   || 0;
        document.getElementById("stat-low").textContent      = stats.low      || 0;

        // Charts
        updateDonut(stats);
        updateLine(stats.total || 0);
        updateBar(allAlerts);

        // Table
        renderTable();

        document.getElementById("last-updated").textContent =
            "Last updated: " + new Date().toLocaleTimeString();

    } catch (err) {
        console.error("Fetch error:", err);
    }
}

// ── Clear Alerts ─────────────────────────
async function clearAlerts() {
    await fetch("/api/alerts", { method: "DELETE" });
    allAlerts = [];
    timeLabels.length = 0;
    timeCounts.length = 0;
    lastTotalAlerts = 0;
    renderTable();
    fetchAlerts();
}

// ── Auto Refresh Every 10s ───────────────
fetchAlerts();
setInterval(fetchAlerts, 10000);