/* ══════════════════════════════════════════
   AEGIS IDS — Main Application JavaScript
   ══════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {

    // ── State ────────────────────────────────
    let allAlerts = [];
    let lineChart = null;
    let donutChart = null;
    let lastTotalAlerts = 0;
    const timeLabels = [];
    const timeCounts = [];
    let currentPage = 1;
    const alertsPerPage = 20;

    // ── DOM Elements ─────────────────────────
    const investigationModal = new bootstrap.Modal(document.getElementById('investigationModal'));
    const investigationContent = document.getElementById('investigation-content');
    const searchInput = document.getElementById('search');
    const severityFilter = document.getElementById('filter-severity');
    const channelFilter = document.getElementById('filter-channel');
    const navLinks = document.querySelectorAll('.sidebar-nav .nav-link');
    const pages = document.querySelectorAll('.page-section');
    const alertTableBody = document.getElementById('alert-body');
    const alertFullTableBody = document.getElementById('alert-body-full');
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const sidebar = document.getElementById('sidebar');
    const pageTitle = document.getElementById('page-title');

    // ── Initialization ───────────────────────
    initEventListeners();
    initWebSocket();
    fetchAlerts();
    setInterval(fetchAlerts, 10000);

    // ── Event Listeners ──────────────────────
    function initEventListeners() {
        // Sidebar navigation
        navLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                navigateTo(link.dataset.page, link);
            });
        });

        // Filters (alerts page)
        searchInput.addEventListener('input', () => { currentPage = 1; renderAllTables(); });
        severityFilter.addEventListener('change', () => { currentPage = 1; renderAllTables(); });
        channelFilter.addEventListener('change', () => { currentPage = 1; renderAllTables(); });

        // Clear alerts button
        document.getElementById('btn-clear-alerts').addEventListener('click', clearAlerts);

        // Export CSV button
        document.getElementById('btn-export').addEventListener('click', exportCSV);

        // Mark investigated button
        document.getElementById('btn-mark-investigated').addEventListener('click', () => {
            investigationModal.hide();
        });

        // Sidebar toggle (mobile)
        if (sidebarToggle) {
            sidebarToggle.addEventListener('click', () => {
                sidebar.classList.toggle('show');
            });
        }
    }

    // ── WebSocket ─────────────────────────────
    function initWebSocket() {
        const ws = new WebSocket(`ws://${location.host}/ws`);
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.type === "NEW_ALERT") {
                console.log("New Live Alert:", data.alert);
                fetchAlerts();
            }
        };
        ws.onerror = () => console.warn("WebSocket error");
        ws.onclose = () => {
            console.warn("WebSocket closed, reconnecting in 5s...");
            setTimeout(initWebSocket, 5000);
        };
    }

    // ══════════════════════════════════════════
    //  NAVIGATION
    // ══════════════════════════════════════════
    function navigateTo(pageId, linkEl) {
        // Hide all sections
        pages.forEach(p => p.style.display = 'none');
        const target = document.getElementById(`page-${pageId}`);
        if (target) target.style.display = 'block';

        // Update nav active state
        navLinks.forEach(a => a.classList.remove('active'));
        if (linkEl) linkEl.classList.add('active');

        const titles = { dashboard: 'Dashboard', alerts: 'Alerts', logs: 'Logs' };
        pageTitle.textContent = titles[pageId] || 'Dashboard';

        // Render page-specific content
        if (pageId === 'alerts') renderAllTables();
        if (pageId === 'logs') renderTimeline();

        // Close mobile sidebar
        sidebar.classList.remove('show');
    }

    // ══════════════════════════════════════════
    //  DATA FETCHING
    // ══════════════════════════════════════════
    async function fetchAlerts() {
        try {
            const [alertRes, statsRes] = await Promise.all([
                fetch("/api/alerts"),
                fetch("/api/stats")
            ]);

            allAlerts = await alertRes.json();
            const stats = await statsRes.json();

            // Update stat cards with animated counters
            animateCounter('stat-total', stats.total || 0);
            animateCounter('stat-critical', stats.critical || 0);
            animateCounter('stat-high', stats.high || 0);
            animateCounter('stat-medium', stats.medium || 0);
            animateCounter('stat-low', stats.low || 0);

            // Update sidebar badge
            const badgeEl = document.getElementById('sidebar-alert-count');
            const critCount = (stats.critical || 0) + (stats.high || 0);
            if (critCount > 0) {
                badgeEl.textContent = critCount;
                badgeEl.style.display = '';
            } else {
                badgeEl.style.display = 'none';
            }

            // Charts
            updateDonut(stats);
            updateLine(stats.total || 0);
            updateTopUsers(allAlerts);

            // Tables
            renderAllTables();
            renderUsersDashboardTable(allAlerts);

            // Host name
            if (allAlerts.length > 0 && allAlerts[0].computer) {
                document.getElementById('host-name').textContent = allAlerts[0].computer;
                document.getElementById('log-hostname').textContent = allAlerts[0].computer;
            } else {
                document.getElementById('host-name').textContent = 'Local Host';
                document.getElementById('log-hostname').textContent = 'Local Host';
            }

            // Last updated
            document.getElementById('last-updated').textContent =
                'Last Scan: ' + new Date().toLocaleTimeString();

        } catch (err) {
            console.error("Fetch error:", err);
        }
    }

    // ── Animated Counter ─────────────────────
    function animateCounter(id, target) {
        const el = document.getElementById(id);
        const current = parseInt(el.textContent) || 0;
        if (current === target) return;

        const diff = target - current;
        const steps = Math.min(Math.abs(diff), 20);
        const increment = diff / steps;
        let step = 0;

        const interval = setInterval(() => {
            step++;
            el.textContent = Math.round(current + increment * step);
            if (step >= steps) {
                el.textContent = target;
                clearInterval(interval);
            }
        }, 30);
    }

    // ══════════════════════════════════════════
    //  TABLE RENDERING
    // ══════════════════════════════════════════
    function getFilteredAlerts() {
        const search = searchInput.value.toLowerCase();
        const severity = severityFilter.value;
        const channel = channelFilter.value;

        return allAlerts.filter(a => {
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
    }

    function renderAllTables() {
        const filtered = getFilteredAlerts();
        renderDashboardTable(filtered.filter(a => a.severity !== "INFO").slice(0, 10));
        renderFullTable(filtered);
    }

    // ── Dashboard Recent Alerts Table ────────
    function renderDashboardTable(alerts) {
        alertTableBody.innerHTML = '';
        if (alerts.length === 0) {
            alertTableBody.innerHTML = `<tr><td colspan="5" class="text-center text-muted py-4">No alerts detected yet</td></tr>`;
            return;
        }
        alerts.forEach(alert => {
            const row = document.createElement('tr');
            row.className = `table-row-${alert.severity.toLowerCase()}`;
            row.innerHTML = `
                <td><strong>${alert.event_id}</strong></td>
                <td><span class="badge text-bg-${getSeverityClass(alert.severity)}">${alert.severity}</span></td>
                <td>${escapeHtml(alert.username || '—')}</td>
                <td>${escapeHtml(alert.ip_address || 'local')}</td>
                <td style="max-width:250px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="${escapeHtml(alert.reason || '')}">${escapeHtml(alert.reason || alert.description || '—')}</td>
            `;
            row.addEventListener('click', () => showInvestigation(alert));
            alertTableBody.appendChild(row);
        });
    }

    // ── Full Alerts Table (with pagination) ──
    function renderFullTable(alerts) {
        if (!alerts) alerts = getFilteredAlerts();

        const totalPages = Math.ceil(alerts.length / alertsPerPage);
        if (currentPage > totalPages) currentPage = Math.max(1, totalPages);

        const start = (currentPage - 1) * alertsPerPage;
        const pageAlerts = alerts.slice(start, start + alertsPerPage);

        alertFullTableBody.innerHTML = '';
        if (pageAlerts.length === 0) {
            alertFullTableBody.innerHTML = `<tr><td colspan="10" class="text-center text-muted py-5">No alerts found</td></tr>`;
        } else {
            pageAlerts.forEach(alert => {
                const row = document.createElement('tr');
                row.className = `table-row-${alert.severity.toLowerCase()}`;
                row.innerHTML = `
                    <td><strong>${alert.event_id}</strong></td>
                    <td><span class="badge text-bg-${getSeverityClass(alert.severity)}">${alert.severity}</span></td>
                    <td>${alert.risk_score}</td>
                    <td style="max-width:280px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="${escapeHtml(alert.reason || '')}">${escapeHtml(alert.reason || '—')}</td>
                    <td>${escapeHtml(alert.username || '—')}</td>
                    <td>${escapeHtml(alert.ip_address || 'local')}</td>
                    <td>${escapeHtml(alert.channel || '—')}</td>
                    <td>${escapeHtml(alert.source || '—')}</td>
                    <td>${escapeHtml(alert.computer || '—')}</td>
                    <td>${escapeHtml(alert.time || '—')}</td>
                `;
                row.addEventListener('click', () => showInvestigation(alert));
                alertFullTableBody.appendChild(row);
            });
        }

        // Update showing text
        document.getElementById('alerts-showing').textContent =
            `Showing ${start + 1}–${Math.min(start + alertsPerPage, alerts.length)} of ${alerts.length} alerts`;

        // Render pagination
        renderPagination(totalPages);
    }

    // ── Pagination ───────────────────────────
    function renderPagination(totalPages) {
        const container = document.getElementById('alerts-pagination');
        container.innerHTML = '';

        if (totalPages <= 1) return;

        // Previous
        const prevLi = document.createElement('li');
        prevLi.className = `page-item ${currentPage === 1 ? 'disabled' : ''}`;
        prevLi.innerHTML = `<a class="page-link" href="#">«</a>`;
        prevLi.addEventListener('click', (e) => { e.preventDefault(); if (currentPage > 1) { currentPage--; renderAllTables(); } });
        container.appendChild(prevLi);

        // Page numbers (show max 5)
        let startPage = Math.max(1, currentPage - 2);
        let endPage = Math.min(totalPages, startPage + 4);
        if (endPage - startPage < 4) startPage = Math.max(1, endPage - 4);

        for (let i = startPage; i <= endPage; i++) {
            const li = document.createElement('li');
            li.className = `page-item ${i === currentPage ? 'active' : ''}`;
            li.innerHTML = `<a class="page-link" href="#">${i}</a>`;
            li.addEventListener('click', (e) => { e.preventDefault(); currentPage = i; renderAllTables(); });
            container.appendChild(li);
        }

        // Next
        const nextLi = document.createElement('li');
        nextLi.className = `page-item ${currentPage === totalPages ? 'disabled' : ''}`;
        nextLi.innerHTML = `<a class="page-link" href="#">»</a>`;
        nextLi.addEventListener('click', (e) => { e.preventDefault(); if (currentPage < totalPages) { currentPage++; renderAllTables(); } });
        container.appendChild(nextLi);
    }

    // ══════════════════════════════════════════
    //  INVESTIGATION MODAL
    // ══════════════════════════════════════════
    function showInvestigation(alert) {
        // Parse mitigations
        let mitigations = [];
        if (alert.mitigation) {
            mitigations = alert.mitigation.split(/[,\n]/).map(s => s.trim()).filter(Boolean);
        }
        if (mitigations.length === 0) {
            mitigations = ["Monitor and review this event", "Check system logs for context"];
        }

        const scoreColor = getScoreColor(alert.risk_score);

        investigationContent.innerHTML = `
            <!-- Header -->
            <div class="d-flex justify-content-between align-items-center mb-3">
                <div>
                    <span class="text-muted">Event ID:</span>
                    <strong class="fs-4 ms-2">${alert.event_id}</strong>
                </div>
                <span class="badge text-bg-${getSeverityClass(alert.severity)} fs-6">${alert.severity}</span>
            </div>

            <!-- Risk Score -->
            <div class="text-center mb-3">
                <div class="risk-score-badge" style="color:${scoreColor}; border-color:${scoreColor};">
                    ${alert.risk_score}
                </div>
                <div class="text-muted mt-1" style="font-size:0.78rem;">Risk Score / 100</div>
            </div>

            <!-- Details -->
            <div class="inv-section-title">Alert Details</div>
            <div class="inv-detail-row"><span class="inv-detail-label">👤 User</span><span class="inv-detail-value">${escapeHtml(alert.username || '—')}</span></div>
            <div class="inv-detail-row"><span class="inv-detail-label">💻 Computer</span><span class="inv-detail-value">${escapeHtml(alert.computer || '—')}</span></div>
            <div class="inv-detail-row"><span class="inv-detail-label">🌐 IP Address</span><span class="inv-detail-value">${escapeHtml(alert.ip_address || 'local')}</span></div>
            <div class="inv-detail-row"><span class="inv-detail-label">📁 Channel</span><span class="inv-detail-value">${escapeHtml(alert.channel || '—')}</span></div>
            <div class="inv-detail-row"><span class="inv-detail-label">🔧 Source</span><span class="inv-detail-value">${escapeHtml(alert.source || '—')}</span></div>
            <div class="inv-detail-row"><span class="inv-detail-label">🕐 Time</span><span class="inv-detail-value">${escapeHtml(alert.time || '—')}</span></div>

            <!-- Attack Type -->
            <div class="inv-section-title">Attack Type</div>
            <p style="font-size:0.88rem; color:#cbd5e1;">${escapeHtml(alert.reason || alert.description || '—')}</p>

            <!-- Mitigations -->
            <div class="inv-section-title">Recommended Mitigation</div>
            <ul class="inv-mitigations list-unstyled">
                ${mitigations.map(m => `<li>✅ ${escapeHtml(m)}</li>`).join("")}
            </ul>

            <!-- Raw Data -->
            <div class="inv-section-title">Raw Event Data</div>
            <div class="raw-data-list">${renderRawData(alert.raw_data)}</div>
        `;

        investigationModal.show();
    }

    // ══════════════════════════════════════════
    //  CHARTS
    // ══════════════════════════════════════════

    // ── Donut Chart ──────────────────────────
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
                    hoverOffset: 8
                }]
            },
            options: {
                plugins: {
                    legend: {
                        position: "right",
                        labels: {
                            color: "#8899aa", font: { size: 12, family: "'Inter', sans-serif" },
                            padding: 16, usePointStyle: true, pointStyle: "circle"
                        }
                    }
                },
                cutout: "68%",
                responsive: true,
                maintainAspectRatio: false
            }
        });
    }

    // ── Line Chart ───────────────────────────
    function updateLine(totalNow) {
        const ctx = document.getElementById("lineChart").getContext("2d");
        const time = new Date().toLocaleTimeString();

        let newAlerts = totalNow - lastTotalAlerts;
        if (lastTotalAlerts === 0 || newAlerts < 0) newAlerts = 0;
        lastTotalAlerts = totalNow;

        if (timeLabels.length >= 12) { timeLabels.shift(); timeCounts.shift(); }
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
                    pointBackgroundColor: "#3b82f6",
                    pointHoverRadius: 6
                }]
            },
            options: {
                scales: {
                    x: {
                        ticks: { color: "#5a6a7a", maxTicksLimit: 6, font: { size: 11 } },
                        grid: { color: "rgba(30,45,69,0.5)" }
                    },
                    y: {
                        ticks: { color: "#5a6a7a", font: { size: 11 } },
                        grid: { color: "rgba(30,45,69,0.5)" },
                        beginAtZero: true
                    }
                },
                plugins: { legend: { display: false } },
                responsive: true,
                maintainAspectRatio: false
            }
        });
    }

    // ── Top Targeted Users ───────────────────
    function updateTopUsers(alerts) {
        const container = document.getElementById("top-users");
        if (!container) return;

        const userCount = {};
        alerts.forEach(a => {
            const u = a.username || "unknown";
            if (u !== "unknown" && u !== "—" && u !== "N/A") userCount[u] = (userCount[u] || 0) + 1;
        });

        const sorted = Object.entries(userCount).sort((a, b) => b[1] - a[1]).slice(0, 5);
        const maxCount = sorted.length ? sorted[0][1] : 1;

        container.innerHTML = sorted.map(([name, count]) => `
            <li>
                <span class="user-name">${escapeHtml(name)}</span>
                <div class="user-bar-wrap">
                    <div class="user-bar" style="width:${(count / maxCount) * 100}%"></div>
                </div>
                <span class="user-count">${count}</span>
            </li>`
        ).join("") || '<li class="text-muted py-3" style="font-size:0.85rem;">No user data yet</li>';
    }

    // ══════════════════════════════════════════
    //  ACTIVITY TIMELINE (Logs Page)
    // ══════════════════════════════════════════
    function renderTimeline() {
        const container = document.getElementById('activity-timeline');
        if (!container) return;

        const recentAlerts = allAlerts.slice(0, 20);

        if (recentAlerts.length === 0) {
            container.innerHTML = '<div class="text-muted text-center py-4">No activity recorded yet</div>';
            return;
        }

        container.innerHTML = recentAlerts.map(a => `
            <div class="timeline-item ${a.severity.toLowerCase()}">
                <div class="timeline-time">${escapeHtml(a.time || '—')}</div>
                <div class="timeline-text">
                    <span class="badge text-bg-${getSeverityClass(a.severity)} me-1">${a.severity}</span>
                    Event <strong>${a.event_id}</strong> — ${escapeHtml(a.reason || a.description || 'Alert detected')}
                </div>
                <div class="timeline-meta">
                    ${escapeHtml(a.username || '—')} · ${escapeHtml(a.channel || '—')} · ${escapeHtml(a.computer || '—')}
                </div>
            </div>
        `).join("");
    }

    // ══════════════════════════════════════════
    //  USERS DASHBOARD TABLE
    // ══════════════════════════════════════════
    function renderUsersDashboardTable(alerts) {
        const container = document.getElementById('users-dashboard-body');
        if (!container) return;

        const userStats = {};
        alerts.forEach(a => {
            const u = a.username || "unknown";
            if (u === "unknown" || u === "—" || u === "N/A") return;

            if (!userStats[u]) {
                userStats[u] = { count: 0, severity: "LOW", ip: "N/A" };
            }
            userStats[u].count++;

            const sevWeight = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
            if (sevWeight[a.severity] > sevWeight[userStats[u].severity]) {
                userStats[u].severity = a.severity;
            }
            if (a.ip_address && a.ip_address !== "local") userStats[u].ip = a.ip_address;
        });

        const sorted = Object.entries(userStats).sort((a, b) => b[1].count - a[1].count).slice(0, 10);

        if (sorted.length === 0) {
            container.innerHTML = '<tr><td colspan="4" class="text-center text-muted py-3">No user data yet</td></tr>';
            return;
        }

        container.innerHTML = sorted.map(([name, data]) => `
            <tr>
                <td><strong>${escapeHtml(name)}</strong></td>
                <td><span class="badge text-bg-${getSeverityClass(data.severity)}">${data.severity}</span></td>
                <td>${data.count}</td>
                <td><code class="text-info">${escapeHtml(data.ip)}</code></td>
            </tr>
        `).join("");
    }

    // ══════════════════════════════════════════
    //  ACTIONS
    // ══════════════════════════════════════════

    // ── Clear Alerts ─────────────────────────
    async function clearAlerts() {
        try {
            const res = await fetch("/api/alerts", { method: "DELETE" });
            if (!res.ok) { console.error("Failed to clear alerts"); return; }
        } catch (err) { console.error("Clear alerts error:", err); return; }

        // Reset all local state
        allAlerts = [];
        timeLabels.length = 0;
        timeCounts.length = 0;
        lastTotalAlerts = 0;
        currentPage = 1;

        // Destroy charts so they re-init cleanly
        if (donutChart) { donutChart.destroy(); donutChart = null; }
        if (lineChart) { lineChart.destroy(); lineChart = null; }

        // Re-render everything immediately
        renderAllTables();
        updateTopUsers([]);

        // Then fetch fresh data from server
        await fetchAlerts();
    }

    // ── Export CSV ────────────────────────────
    function exportCSV() {
        const filtered = getFilteredAlerts();
        if (filtered.length === 0) { alert("No alerts to export."); return; }

        const headers = ['Event ID', 'Severity', 'Risk Score', 'Description', 'Username', 'IP Address', 'Channel', 'Source', 'Computer', 'Time'];
        const rows = filtered.map(a => [
            a.event_id, a.severity, a.risk_score,
            `"${(a.reason || a.description || '').replace(/"/g, '""')}"`,
            a.username || '', a.ip_address || '', a.channel || '',
            a.source || '', a.computer || '', a.time || ''
        ]);

        const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `windows_ids_alerts_${new Date().toISOString().slice(0, 10)}.csv`;
        link.click();
        URL.revokeObjectURL(url);
    }

    // ══════════════════════════════════════════
    //  UTILITIES
    // ══════════════════════════════════════════
    function getSeverityClass(severity) {
        const map = { CRITICAL: 'danger', HIGH: 'warning', MEDIUM: 'info', LOW: 'success', INFO: 'secondary' };
        return map[severity] || 'secondary';
    }

    function getScoreColor(score) {
        if (score >= 80) return '#ef4444';
        if (score >= 60) return '#f97316';
        if (score >= 40) return '#eab308';
        return '#22c55e';
    }

    function escapeHtml(unsafe) {
        if (typeof unsafe !== 'string') return String(unsafe);
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function renderRawData(rawStr) {
        if (!rawStr || rawStr === "[]") return '<span class="text-muted">No raw data available.</span>';
        try {
            const data = JSON.parse(rawStr);
            if (Array.isArray(data) && data.length > 0) {
                return `<ul class="raw-data-list mb-0">` +
                    data.map((d, i) => `<li><span class="raw-idx">[${i}]</span> ${escapeHtml(d)}</li>`).join("") +
                    `</ul>`;
            }
        } catch (e) {
            return `<pre class="text-muted" style="font-size:0.78rem;">${escapeHtml(rawStr)}</pre>`;
        }
        return '<span class="text-muted">No raw data available.</span>';
    }

    // Make navigateTo available globally for any inline handlers
    window.navigateTo = navigateTo;
});