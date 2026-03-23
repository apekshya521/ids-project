/* ══════════════════════════════════════════

   ══════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {

    // ── State ────────────────────────────────
    let allAlerts = [];
    let allLogs = [];
    let lineChart = null;
    let donutChart = null;
    let lastTotalAlerts = {};
    const timeLabels = [];
    const timeCounts = [];
    let currentPage = 1;
    const alertsPerPage = 1000;
    let currentDeviceId = 'all';
    let remoteDevices = [];
    /** Hostname of the machine running the IDS (shown when scope = local) */
    let localSystemHostname = '';

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
    const deviceSelector = document.getElementById('device-selector');

    // ── Initialization ───────────────────────
    initEventListeners();
    initWebSocket();
    fetchRemoteDevices(); // Fetch devices first
    fetchAlerts();
    fetchLogsForDashboard();
    setInterval(fetchAlerts, 10000);
    setInterval(fetchLogsForDashboard, 15000);

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

        // Sidebar toggle (mobile)
        if (sidebarToggle) {
            sidebarToggle.addEventListener('click', () => {
                sidebar.classList.toggle('show');
            });
        }

        // Stat cards click handlers - navigate to alerts with filter
        document.querySelectorAll('.clickable-card').forEach(card => {
            card.addEventListener('click', () => {
                const severity = card.dataset.severity;
                severityFilter.value = severity;
                currentPage = 1;
                navigateTo('alerts', document.getElementById('nav-alerts'));
                renderAllTables();
            });
        });

        // Device selector change
        deviceSelector.addEventListener('change', () => {
            currentDeviceId = deviceSelector.value;
            updateDashboardForDevice();
        });
    }

    async function fetchRemoteDevices() {
        try {
            const res = await fetch("/api/remote/devices");
            const data = await res.json();
            remoteDevices = data.devices || [];
            
            // Populate selector
            remoteDevices.forEach(dev => {
                const opt = document.createElement('option');
                opt.value = dev.device_id;
                opt.textContent = dev.name || dev.device_id;
                deviceSelector.appendChild(opt);
            });
        } catch (err) {
            console.error("Error fetching remote devices:", err);
        }
    }

    function updateDashboardForDevice() {
        const scopeEl = document.getElementById('current-device-scope');
        if (!scopeEl) return;
        if (currentDeviceId === 'all') {
            scopeEl.textContent = 'All devices';
        } else if (currentDeviceId === 'local') {
            scopeEl.textContent = localSystemHostname || 'Local';
        } else {
            const dev = remoteDevices.find(d => d.device_id === currentDeviceId);
            scopeEl.textContent = dev ? (dev.name || dev.ip || currentDeviceId) : currentDeviceId;
        }

        currentPage = 1;
        renderAllTables();
        updateStats();
    }

    // ── WebSocket ─────────────────────────────
    function initWebSocket() {
        const wsUrl = `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws`;
        const ws = new WebSocket(wsUrl);
        ws.onmessage = (event) => {
            let data;
            try {
                data = JSON.parse(event.data);
            } catch (e) {
                console.warn('WebSocket: ignore non-JSON message', e);
                return;
            }
            if (data.type === "NEW_ALERT") {
                console.log("New Live Event:", data.alert);
                
                // Check for duplicate (same event_id and time)
                const isDuplicate = allAlerts.some(existing => 
                    existing.event_id === data.alert.event_id && 
                    existing.time === data.alert.time
                );
                
                if (!isDuplicate) {
                    // Add event to the beginning of allAlerts array
                    allAlerts.unshift(data.alert);
                    // Limit to 1000 most recent events
                    if (allAlerts.length > 1000) {
                        allAlerts.pop();
                    }
                    // Update all tables and charts
                    renderAllTables();
                    updateStats();
                } else {
                    console.log("Skipping duplicate event:", data.alert.event_id, data.alert.time);
                }
            } else if (data.type === "NEW_LOG") {
                // Check for duplicate (same event_id and time)
                const isDuplicateLog = allLogs.some(existing => 
                    existing.event_id === data.log.event_id && 
                    existing.time === data.log.time
                );
                
                if (!isDuplicateLog) {
                    // Add log to the beginning of allLogs array
                    allLogs.unshift(data.log);
                    // Limit to 200 most recent logs
                    if (allLogs.length > 200) {
                        allLogs.pop();
                    }
                    // Update dashboard table to show the new log instantly (respecting filter)
                    const filteredLogs = allLogs.filter(log => {
                        if (currentDeviceId === 'local') return log.source_type === 'local' || !log.device_id || log.device_id === 'local';
                        if (currentDeviceId !== 'all') return log.device_id === currentDeviceId;
                        return true;
                    });
                    renderDashboardTable(filteredLogs.slice(0, 10));
                }
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
        if (pageId === 'logs') fetchLogsAndRender();

        // Close mobile sidebar
        sidebar.classList.remove('show');
    }

    // ══════════════════════════════════════════
    //  DATA FETCHING
    // ══════════════════════════════════════════
    async function fetchAlerts() {
        try {
            console.log("DEBUG: Fetching alerts and stats...");
            const [alertRes, statsRes] = await Promise.all([
                fetch("/api/alerts?limit=5000&window_minutes=43200"),  // 30 days - show ALL
                fetch("/api/stats?window_minutes=43200")              // 30 days - show ALL
            ]);

            allAlerts = await alertRes.json();
            const stats = await statsRes.json();
            console.log("DEBUG: Received stats:", stats);

            localSystemHostname = stats.host || '';

            const logHostEl = document.getElementById('log-hostname');
            if (logHostEl) logHostEl.textContent = localSystemHostname || 'Unknown';

            // Update local option in dropdown
            const localOpt = Array.from(deviceSelector.options).find(o => o.value === 'local');
            if (localOpt && stats.host) {
                localOpt.textContent = `Local: ${stats.host}`;
            }

            // Update entire dashboard (this automatically updates filtered stats, counters, and charts)
            if (typeof updateDashboardForDevice === 'function') updateDashboardForDevice();

            // Last updated
            const lastUpdatedEl = document.getElementById('last-updated');
            if (lastUpdatedEl) {
                lastUpdatedEl.textContent = 'Last Scan: ' + new Date().toLocaleTimeString();
            }

        } catch (err) {
            console.error("CRITICAL: Fetch error in fetchAlerts:", err);
        }
    }

    async function fetchLogsForDashboard() {
        try {
            console.log("DEBUG: Fetching logs for dashboard...");
            const logsRes = await fetch("/api/logs?limit=100&window_minutes=1440"); // Last 24 hours
            allLogs = await logsRes.json();
            console.log("DEBUG: Received logs for dashboard:", allLogs.length);
            renderAllTables();
            updateStats();
        } catch (err) {
            console.error("Error fetching logs for dashboard:", err);
        }
    }

    async function fetchLogsAndRender() {
        try {
            // Fetch local logs
            const resLocal = await fetch(`/api/logs?limit=50&device_id=local&window_minutes=1440`);
            const localLogs = await resLocal.json();
            renderTimeline('timeline-local', localLogs);

            // Fetch remote logs (using the FIRST remote device found, or fallback)
            let devId = null;
            if (deviceSelector.value !== 'all' && deviceSelector.value !== 'local') {
                devId = deviceSelector.value;
            } else if (remoteDevices && remoteDevices.length > 0) {
                devId = remoteDevices[0].device_id;
            }

            if (devId) {
                const resRemote = await fetch(`/api/logs?limit=50&device_id=${devId}&window_minutes=1440`);
                const remoteLogs = await resRemote.json();
                renderTimeline('timeline-remote', remoteLogs);
            } else {
                const container = document.getElementById('timeline-remote');
                if (container) container.innerHTML = '<div class="text-muted text-center py-4">No remote device configured</div>';
            }
            
        } catch (err) {
            console.error("Error fetching logs:", err);
        }
    }

    // ── Animated Counter ─────────────────────
    function animateCounter(id, target) {
        const el = document.getElementById(id);
        if (!el) return;
        
        // Defensive check - if already at target, skip
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
    /** Filter an alert list by search, severity, channel, and current device (defaults to allAlerts). */
    function filterAlertsList(sourceAlerts) {
        const search = searchInput.value.toLowerCase();
        const severity = severityFilter.value;
        const channel = channelFilter.value;

        return sourceAlerts.filter(a => {
            const matchSearch = !search ||
                (a.username || "").toLowerCase().includes(search) ||
                (a.ip_address || "").toLowerCase().includes(search) ||
                (a.reason || "").toLowerCase().includes(search) ||
                (a.description || "").toLowerCase().includes(search) ||
                String(a.event_id).includes(search);
            const matchSev = !severity || a.severity === severity;
            const matchChan = !channel || a.channel === channel;
            
            // Device filter
            let matchDev = true;
            if (currentDeviceId === 'local') {
                matchDev = a.source_type === 'local' || !a.device_id || a.device_id === 'local';
            } else if (currentDeviceId !== 'all') {
                matchDev = a.device_id === currentDeviceId;
            }
            return matchSearch && matchSev && matchChan && matchDev;
        });
    }

    function getFilteredAlerts() {
        return filterAlertsList(allAlerts);
    }

    function renderAllTables() {
        // Dashboard recent table: respect device scope (same as updateStats)
        const filteredLogs = allLogs.filter(log => {
            if (currentDeviceId === 'local') return log.source_type === 'local' || !log.device_id || log.device_id === 'local';
            if (currentDeviceId !== 'all') return log.device_id === currentDeviceId;
            return true;
        });
        renderDashboardTable(filteredLogs.slice(0, 10));

        // Alerts page: all severities (filters + stat-card clicks e.g. INFO)
        renderFullTable(filterAlertsList(allAlerts));
    }

    // ── Dashboard Recent Logs Table ────────
    function renderDashboardTable(logs) {
        alertTableBody.innerHTML = '';
        if (logs.length === 0) {
            alertTableBody.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4">No logs detected yet</td></tr>`;
            return;
        }
        logs.forEach(log => {
            const row = document.createElement('tr');
            // For logs, we don't have severity, so use a default
            const severity = log.severity || 'INFO';
            row.className = `table-row-${severity.toLowerCase()}`;
            const devName = log.device_name || (log.source_type === 'remote' ? log.device_id : 'Local');
            const timeDisplay = formatDashboardTimestamp(log.time);
            row.innerHTML = `
                <td><strong>${log.event_id}</strong></td>
                <td class="text-nowrap"><small class="dashboard-ts">${escapeHtml(timeDisplay)}</small></td>
                <td><span class="badge text-bg-${getSeverityClass(severity)}">${severity}</span></td>
                <td><small class="text-muted">${escapeHtml(devName)}</small></td>
                <td>${escapeHtml(log.username || '—')}</td>
                <td>${escapeHtml(log.ip_address || 'local')}</td>
                <td style="max-width:250px;" title="${escapeHtml(log.message || '')}">${isLongText(log.message) ? 
                        `<div>
                            <span>${escapeHtml(truncateText(log.message || '—', 80))}</span>
                            <button type="button" class="btn btn-sm btn-link p-0 ms-1" onclick="toggleTableCell(this, '${escapeHtml(log.message || '—').replace(/'/g, "\\'")}')">
                                <i class="bi bi-chevron-down"></i>
                            </button>
                        </div>` : 
                        escapeHtml(log.message || '—')}</td>
            `;
            // Make logs clickable - convert log to alert-like format for investigation
            row.addEventListener('click', () => showLogInvestigation(log));
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
                const sevKey = (alert.severity != null ? String(alert.severity) : 'INFO').toLowerCase();
                row.className = `table-row-${sevKey}`;
                const devName = alert.device_name || (alert.source_type === 'remote' ? alert.device_id : 'Local');
                row.innerHTML = `
                    <td><strong>${alert.event_id}</strong></td>
                    <td><span class="badge text-bg-${getSeverityClass(alert.severity)}">${alert.severity}</span></td>
                    <td><small class="text-muted">${escapeHtml(devName)}</small></td>
                    <td>${alert.risk_score}</td>
                    <td style="max-width:280px;" title="${escapeHtml(alert.reason || '')}">${isLongText(alert.reason) ? 
                        `<div>
                            <span>${escapeHtml(truncateText(alert.reason || '—', 100))}</span>
                            <button type="button" class="btn btn-sm btn-link p-0 ms-1" onclick="toggleTableCell(this, '${escapeHtml(alert.reason || '—').replace(/'/g, "\\'")}')">
                                <i class="bi bi-chevron-down"></i>
                            </button>
                        </div>` : 
                        escapeHtml(alert.reason || '—')}</td>
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
        // Check for evidence destruction events (reason and/or message)
        const reason = (alert.reason || '').toLowerCase();
        const message = (alert.message || '').toLowerCase();
        const isEvidenceDestruction =
            reason.includes('audit log cleared') ||
            reason.includes('log cleared') ||
            reason.includes('log deleted') ||
            reason.includes('evidence destruction') ||
            message.includes('audit log cleared') ||
            message.includes('log cleared');

        // Parse mitigations
        let mitigations = [];
        if (alert.mitigation) {
            mitigations = alert.mitigation.split(/[,\n]/).map(s => s.trim()).filter(Boolean);
        }
        
        // Add special mitigations for evidence destruction
        if (isEvidenceDestruction) {
            mitigations.unshift(" IMMEDIATE INVESTIGATION REQUIRED - Potential evidence destruction");
            mitigations.push("Check system logs for tampering indicators");
            mitigations.push("Review user permissions and access logs");
            mitigations.push("Consider forensic image preservation");
            mitigations.push("Document incident for legal compliance");
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
                    ${isEvidenceDestruction ? '<span class="badge text-bg-danger ms-2">⚠️ EVIDENCE DESTRUCTION</span>' : ''}
                </div>
                <span class="badge text-bg-${getSeverityClass(alert.severity)} fs-6">${alert.severity}</span>
            </div>

            <!-- Risk Score -->
            <div class="text-center mb-3">
                <div class="risk-score-badge ${isEvidenceDestruction ? 'evidence-destruction' : ''}" style="color:${isEvidenceDestruction ? '#dc3545' : scoreColor}; border-color:${isEvidenceDestruction ? '#dc3545' : scoreColor};">
                    ${isEvidenceDestruction ? '🚨' : ''}${alert.risk_score}
                </div>
                <div class="text-muted mt-1" style="font-size:0.78rem;">Risk Score / 100 ${isEvidenceDestruction ? '(CRITICAL)' : ''}</div>
            </div>

            <!-- Evidence Destruction Warning -->
            ${isEvidenceDestruction ? `
                <div class="alert alert-danger d-flex align-items-center mb-3" role="alert">
                    <div class="me-2">🚨</div>
                    <div>
                        <strong>Evidence Destruction Detected!</strong><br>
                        <small>This event indicates potential tampering with audit logs. Immediate investigation required.</small>
                    </div>
                </div>
            ` : ''}

            <!-- Details -->
            <div class="inv-section-title">Alert Details</div>
            <div class="inv-detail-row"><span class="inv-detail-label"> User</span><span class="inv-detail-value">${escapeHtml(alert.username || '—')}</span></div>
            <div class="inv-detail-row"><span class="inv-detail-label"> Computer</span><span class="inv-detail-value">${escapeHtml(alert.computer || '—')}</span></div>
            <div class="inv-detail-row"><span class="inv-detail-label"> IP Address</span><span class="inv-detail-value">${escapeHtml(alert.ip_address || 'local')}</span></div>
            <div class="inv-detail-row"><span class="inv-detail-label"> Channel</span><span class="inv-detail-value">${escapeHtml(alert.channel || '—')}</span></div>
            <div class="inv-detail-row"><span class="inv-detail-label"> Source</span><span class="inv-detail-value">${escapeHtml(alert.source || '—')}</span></div>
            <div class="inv-detail-row"><span class="inv-detail-label"> Time</span><span class="inv-detail-value">${escapeHtml(alert.time || '—')}</span></div>

            <!-- Event Description -->
            <div class="inv-section-title">Event Description</div>
            <div id="event-description-container">
                <p style="font-size:0.88rem; color:#cbd5e1;" id="event-description-short">${escapeHtml(truncateText(alert.reason || alert.description || '—', 150))}</p>
                <p style="font-size:0.88rem; color:#cbd5e1; display:none;" id="event-description-full">${escapeHtml(alert.reason || alert.description || '—')}</p>
                ${isLongText(alert.reason || alert.description) ? `<button type="button" class="btn btn-sm btn-outline-secondary mt-2" id="btn-toggle-description" onclick="toggleEventDescription()">
                    <span id="toggle-text">Show More</span>
                    <i class="bi bi-chevron-down ms-1" id="toggle-icon"></i>
                </button>` : ''}
            </div>

            <!-- Mitigations -->
            <div class="inv-section-title">Recommended Mitigation</div>
            <ul class="inv-mitigations list-unstyled">
                ${mitigations.map(m => `<li> ${escapeHtml(m)}</li>`).join("")}
            </ul>
        `;

        investigationModal.show();
    }

    // ── Log Investigation Modal ─────────────────
    function showLogInvestigation(log) {
        // Parse raw_data if it's a JSON string, otherwise use the log object directly
        let rawData = {};
        try {
            if (log.raw_data) {
                rawData = JSON.parse(log.raw_data);
            }
        } catch (e) {
            // If parsing fails, use the log object as raw data
            rawData = log;
        }

        // Check for evidence destruction events in logs
        const isEvidenceDestruction = (
            (log.message && log.message.toLowerCase().includes('audit log cleared')) ||
            (log.message && log.message.toLowerCase().includes('log cleared')) ||
            (log.message && log.message.toLowerCase().includes('log deleted')) ||
            (rawData.Message && rawData.Message.toLowerCase().includes('audit log cleared')) ||
            (rawData.Description && rawData.Description.toLowerCase().includes('audit log cleared'))
        );

        // Convert log to alert-like format for consistent display
        const alertLikeData = {
            event_id: log.event_id,
            severity: isEvidenceDestruction ? 'CRITICAL' : (log.severity || 'INFO'),
            risk_score: isEvidenceDestruction ? 95 : (log.risk_score || 0),
            username: log.username || rawData.UserName || 'System',
            computer: log.computer || log.device_name || rawData.Computer || 'Unknown',
            ip_address: log.ip_address || 'local',
            channel: log.channel || rawData.Channel || 'System',
            source: log.source || log.source_type || 'Local',
            time: log.time || log.created_at || rawData.TimeCreated || 'Unknown',
            reason: log.message || log.description || rawData.Message || rawData.Description || 'System Log Entry',
            description: log.message || log.description || rawData.Message || rawData.Description || 'System Log Entry',
            raw_data: log.raw_data || JSON.stringify(rawData, null, 2),
            mitigation: isEvidenceDestruction ? 
                '🚨 IMMEDIATE INVESTIGATION REQUIRED - Potential evidence destruction. Check system logs for tampering indicators, review user permissions, consider forensic preservation.' :
                'Monitor this log entry for patterns and investigate if suspicious'
        };

        // Use the existing showInvestigation function with converted data
        showInvestigation(alertLikeData);
    }

    // ══════════════════════════════════════════
    //  CHARTS
    // ══════════════════════════════════════════

    function updateStats() {
        // Filter alerts based on current device
        const filteredForStats = allAlerts.filter(a => {
            if (currentDeviceId === 'local') return a.source_type === 'local' || !a.device_id || a.device_id === 'local';
            if (currentDeviceId !== 'all') return a.device_id === currentDeviceId;
            return true;
        });

        // Recalculate stats from filtered alerts
        const stats = {
            total: filteredForStats.length,
            critical: filteredForStats.filter(a => a.severity === 'CRITICAL').length,
            high: filteredForStats.filter(a => a.severity === 'HIGH').length,
            medium: filteredForStats.filter(a => a.severity === 'MEDIUM').length,
            low: filteredForStats.filter(a => a.severity === 'LOW').length,
            info: filteredForStats.filter(a => a.severity === 'INFO').length
        };
        
        // Update stat cards
        animateCounter('stat-total', stats.total);
        animateCounter('stat-critical', stats.critical);
        animateCounter('stat-high', stats.high);
        animateCounter('stat-medium', stats.medium);
        animateCounter('stat-low', stats.low);
        animateCounter('stat-info', stats.info);

        // Update sidebar badge
        const badgeEl = document.getElementById('sidebar-alert-count');
        if (badgeEl) {
            const critCount = stats.critical + stats.high;
            if (critCount > 0) {
                badgeEl.textContent = critCount;
                badgeEl.style.display = '';
            } else {
                badgeEl.style.display = 'none';
            }
        }
        
        // Update charts with filtered data
        updateDonut(stats);
        updateLine(stats.total);
        updateTopUsers(filteredForStats);
        
        // Filter dashboard table (recent logs)
        const filteredLogs = allLogs.filter(log => {
            if (currentDeviceId === 'local') return log.source_type === 'local' || !log.device_id || log.device_id === 'local';
            if (currentDeviceId !== 'all') return log.device_id === currentDeviceId;
            return true;
        });

        // Update dashboard table
        renderDashboardTable(filteredLogs.slice(0, 10));
        renderUsersDashboardTable(filteredForStats);
    }

    // ── Donut Chart ──────────────────────────
    function updateDonut(stats) {
        const ctx = document.getElementById("donutChart").getContext("2d");
        const labels = ["Critical", "High", "Medium", "Low", "Info"];
        const data = [stats.critical, stats.high, stats.medium, stats.low, stats.info];
        const backgroundColor = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#3b82f6"];
        const severityMap = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

        if (donutChart) {
            donutChart.data.labels = labels;
            donutChart.data.datasets[0].data = data;
            donutChart.data.datasets[0].backgroundColor = backgroundColor;
            donutChart.update();
            return;
        }
        donutChart = new Chart(ctx, {
            type: "doughnut",
            data: {
                labels,
                datasets: [{
                    data,
                    backgroundColor,
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
                        },
                        onClick: (e, legendItem) => {
                            const severity = severityMap[legendItem.index];
                            severityFilter.value = severity;
                            currentPage = 1;
                            navigateTo('alerts', document.getElementById('nav-alerts'));
                            renderAllTables();
                        }
                    }
                },
                onClick: (e, elements) => {
                    if (elements.length > 0) {
                        const severity = severityMap[elements[0].index];
                        severityFilter.value = severity;
                        currentPage = 1;
                        navigateTo('alerts', document.getElementById('nav-alerts'));
                        renderAllTables();
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

        let previousTotal = lastTotalAlerts[currentDeviceId] || 0;
        let newAlerts = totalNow - previousTotal;
        if (previousTotal === 0 || newAlerts < 0) newAlerts = 0;
        lastTotalAlerts[currentDeviceId] = totalNow;

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
    function renderTimeline(containerId, logs) {
        const container = document.getElementById(containerId);
        if (!container) return;

        if (!logs || logs.length === 0) {
            container.innerHTML = '<div class="text-muted text-center py-4">No activity recorded yet</div>';
            return;
        }

        container.innerHTML = logs.map(a => {
            const sev = a.severity || 'INFO';
            const sevClass = (a.severity || 'low').toLowerCase();
            const badgeClass = typeof getSeverityClass === 'function' ? getSeverityClass(sev) : 'secondary';
            const devLabel = a.device_id === 'local' ? 'Local' : (a.device_name || a.device_id || 'Remote');

            return `
                <div class="timeline-item ${sevClass}">
                    <div class="timeline-time">${escapeHtml(a.time || '—')}</div>
                    <div class="timeline-text">
                        <span class="badge text-bg-${badgeClass} me-1" style="font-size:0.65rem; padding: 0.2rem 0.4rem;">${sev}</span>
                        Event <strong>${a.event_id}</strong> — ${isLongText(a.reason || a.message) ? 
                            `<span class="timeline-truncated" data-full="${(a.reason || a.message || 'System Log').replace(/"/g, '&quot;')}">${escapeHtml(truncateText(a.reason || a.message || 'System Log', 120))}</span>
                            <button type="button" class="btn btn-sm btn-link p-0 ms-1 timeline-toggle" style="font-size:0.7rem;" onclick="toggleTimelineText(this)">
                                <i class="bi bi-chevron-down"></i>
                            </button>` : 
                            escapeHtml(a.reason || a.message || 'System Log')}
                    </div>
                    <div class="timeline-meta">
                        ${escapeHtml(a.username || 'System')} · ${escapeHtml(a.channel || '—')} · ${escapeHtml(devLabel)}
                    </div>
                </div>
            `;
        }).join("");
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
        lastTotalAlerts = {};
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
        try {
            const filtered = getFilteredAlerts();
            if (filtered.length === 0) { 
                alert("No alerts to export. Please apply filters or wait for alerts to be generated."); 
                return; 
            }

            // Show loading state
            const exportBtn = document.getElementById('btn-export');
            const originalText = exportBtn.innerHTML;
            exportBtn.innerHTML = '<i class="bi bi-hourglass-split me-1"></i>Exporting...';
            exportBtn.disabled = true;

            // CSV Headers
            const headers = ['Event ID', 'Severity', 'Risk Score', 'Description', 'Username', 'IP Address', 'Channel', 'Source', 'Computer', 'Device', 'Time'];
            
            // CSV Rows with proper escaping
            const rows = filtered.map(a => [
                a.event_id || '',
                a.severity || '',
                a.risk_score || '',
                `"${(a.reason || a.description || '').replace(/"/g, '""')}"`,
                `"${(a.username || '').replace(/"/g, '""')}"`,
                `"${(a.ip_address || '').replace(/"/g, '""')}"`,
                `"${(a.channel || '').replace(/"/g, '""')}"`,
                `"${(a.source || '').replace(/"/g, '""')}"`,
                `"${(a.computer || '').replace(/"/g, '""')}"`,
                `"${(a.device_name || 'Local').replace(/"/g, '""')}"`,
                `"${(a.time || '').replace(/"/g, '""')}"`
            ]);

            // Create CSV content
            const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
            
            // Add BOM for proper UTF-8 handling in Excel
            const BOM = '\uFEFF';
            const csvContent = BOM + csv;

            // Create and trigger download
            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `windows_ids_alerts_${new Date().toISOString().slice(0, 10)}.csv`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);

            // Show success feedback
            exportBtn.innerHTML = '<i class="bi bi-check-circle me-1"></i>Exported!';
            setTimeout(() => {
                exportBtn.innerHTML = originalText;
                exportBtn.disabled = false;
            }, 2000);

        } catch (error) {
            console.error('Export failed:', error);
            alert('Export failed. Please try again.');
            
            // Reset button state
            const exportBtn = document.getElementById('btn-export');
            exportBtn.innerHTML = '<i class="bi bi-download me-1"></i>Export CSV';
            exportBtn.disabled = false;
        }
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

    /** Format log/alert time for dashboard (API uses "YYYY-MM-DD HH:MM:SS"). */
    function formatDashboardTimestamp(raw) {
        if (raw == null || String(raw).trim() === '') return '—';
        const s = String(raw).trim();
        const asIso = s.includes('T') ? s : s.replace(' ', 'T');
        let d = new Date(asIso);
        if (Number.isNaN(d.getTime())) d = new Date(s);
        if (Number.isNaN(d.getTime())) return s;
        return d.toLocaleString(undefined, {
            month: 'short',
            day: 'numeric',
            year: 'numeric',
            hour: 'numeric',
            minute: '2-digit',
            second: '2-digit',
            hour12: true
        });
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
            
            // If it's an array with one object, extract the object
            if (Array.isArray(data) && data.length === 1 && typeof data[0] === 'object') {
                return renderRawDataObject(data[0]);
            }
            
            // If it's an array with multiple items, display as list
            if (Array.isArray(data) && data.length > 0) {
                return `<ul class="raw-data-list mb-0">` +
                    data.map((d, i) => {
                        if (typeof d === 'object') {
                            return `<li><span class="raw-idx">[${i}]</span> ${renderRawDataObject(d)}</li>`;
                        } else {
                            return `<li><span class="raw-idx">[${i}]</span> ${escapeHtml(String(d))}</li>`;
                        }
                    }).join("") +
                    `</ul>`;
            }
            
            // If it's an object, display as key-value pairs
            if (typeof data === 'object' && data !== null) {
                return renderRawDataObject(data);
            }
            
        } catch (e) {
            // If parsing fails, display as plain text
            return `<pre class="text-muted" style="font-size:0.78rem;">${escapeHtml(rawStr)}</pre>`;
        }
        
        return '<span class="text-muted">No raw data available.</span>';
    }

    function renderRawDataObject(obj) {
        if (!obj || typeof obj !== 'object') return '';
        
        const entries = Object.entries(obj).map(([key, value]) => {
            const displayValue = typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value);
            return `<div class="raw-data-item">
                <span class="raw-data-key">${escapeHtml(key)}:</span>
                <span class="raw-data-value">${escapeHtml(displayValue)}</span>
            </div>`;
        }).join('');
        
        return `<div class="raw-data-object">${entries}</div>`;
    }

    // Make navigateTo available globally for any inline handlers
    window.navigateTo = navigateTo;
});

// ── Helper Functions for Event Description ──
function truncateText(text, maxLength) {
    if (!text || text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

function isLongText(text) {
    return text && text.length > 150;
}

function toggleEventDescription() {
    const shortDesc = document.getElementById('event-description-short');
    const fullDesc = document.getElementById('event-description-full');
    const toggleBtn = document.getElementById('btn-toggle-description');
    const toggleText = document.getElementById('toggle-text');
    const toggleIcon = document.getElementById('toggle-icon');
    
    if (fullDesc.style.display === 'none') {
        // Show full description
        shortDesc.style.display = 'none';
        fullDesc.style.display = 'block';
        toggleText.textContent = 'Show Less';
        toggleIcon.className = 'bi bi-chevron-up ms-1';
    } else {
        // Show short description
        shortDesc.style.display = 'block';
        fullDesc.style.display = 'none';
        toggleText.textContent = 'Show More';
        toggleIcon.className = 'bi bi-chevron-down ms-1';
    }
}

function toggleTableCell(button, fullText) {
    const container = button.parentElement;
    const span = container.querySelector('span');
    const icon = button.querySelector('i');
    
    if (button.dataset.expanded === 'true') {
        // Show truncated version
        span.textContent = truncateText(fullText, container.parentElement.id === 'alert-body-full' ? 100 : 80);
        icon.className = 'bi bi-chevron-down';
        button.dataset.expanded = 'false';
    } else {
        // Show full text
        span.textContent = fullText;
        icon.className = 'bi bi-chevron-up';
        button.dataset.expanded = 'true';
    }
}

function toggleTimelineText(button) {
    const span = button.previousElementSibling;
    const icon = button.querySelector('i');
    const fullText = span.dataset.full;
    
    if (button.dataset.expanded === 'true') {
        // Show truncated version
        span.textContent = truncateText(fullText, 120);
        icon.className = 'bi bi-chevron-down';
        button.dataset.expanded = 'false';
    } else {
        // Show full text
        span.textContent = fullText;
        icon.className = 'bi bi-chevron-up';
        button.dataset.expanded = 'true';
    }
}
