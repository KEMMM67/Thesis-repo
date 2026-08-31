console.log('[admin_dashboard] Script parsed. Waiting for DOMContentLoaded...');

document.addEventListener('DOMContentLoaded', () => {
    console.log('[admin_dashboard] DOMContentLoaded fired. Beginning initialization.');

    // =============================================================
    // CONFIG + SHARED HELPERS
    // =============================================================
    const API_BASE = 'http://localhost:3000';

    // Escapes text before it goes into innerHTML, so data that
    // ultimately traces back to user input (a log's user_email is
    // whatever someone typed into the login form; a prompt() value
    // is typed directly by this admin) can never be interpreted as
    // markup.
    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str == null ? '' : String(str);
        return div.innerHTML;
    }

    // Explainable Score UI (SE traceability requirement): every
    // SECURITY_EVALUATION log's description now arrives from
    // middleware/securityMiddleware.js formatted as
    // "<narrative> | <formula>" (see core/scorer.js's computeScore()
    // for where the formula comes from). Splitting on that one fixed
    // delimiter - no regex, nothing fragile - separates the two so the
    // formula can be styled distinctly instead of buried in a wall of
    // prose. Logs that predate this feature, or don't carry a formula
    // (e.g. LOGIN_SUCCESS), simply have no " | " to split on and render
    // exactly as before.
    function renderLogDescription(description) {
        const text = description || '';
        const sepIndex = text.indexOf(' | ');
        if (sepIndex === -1) return escapeHtml(text);

        const narrative = text.slice(0, sepIndex);
        const formula = text.slice(sepIndex + 3);
        return `${escapeHtml(narrative)}<br><code class="score-formula">${escapeHtml(formula)}</code>`;
    }

    // Same device-fingerprint computation script.js runs at login,
    // duplicated here rather than shared: admin_dashboard.html has
    // always been a self-contained page (no <script src="script.js">),
    // and script.js assumes a #loginForm exists on the page it's
    // loaded into, so it can't just be included as-is. Recomputed on
    // every call rather than cached - it's a pure, practically-free
    // local computation (no network I/O), same as the login flow.
    async function getDeviceFingerprint() {
        const data = [
            navigator.userAgent,
            navigator.language,
            screen.colorDepth,
            screen.width + 'x' + screen.height,
            new Date().getTimezoneOffset()
        ].join('|');

        let hash = 0;
        for (let i = 0; i < data.length; i++) {
            const char = data.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return "DEV-" + Math.abs(hash).toString(16);
    }

    // Clears the stored session and sends the admin back to the
    // Admin Portal login page - not index.html, which is the
    // *student* portal now that logins are split. Used for "never
    // logged in", "server rejected the token" (401/403 - see
    // authFetch() below), and manual Logout clicks.
    function goToLogin() {
        localStorage.removeItem('authToken');
        localStorage.removeItem('userEmail');
        window.location.href = 'admin_login.html';
    }

    // Every fetch() against an authMiddleware-protected route goes
    // through here instead of calling fetch() directly, so token
    // attachment, device telemetry, and session-expiry handling
    // only need to be correct in one place. Two headers go on
    // every call:
    //   - Authorization: Bearer <token>  - who authMiddleware and
    //     requireRole believe you are.
    //   - x-device-id                    - the same behavioral
    //     signal the login form sends, so securityMiddleware's
    //     velocity and endpoint-weight scoring (core/scorer.js)
    //     can attribute these authenticated admin actions to a
    //     device too, not just login attempts.
    //
    // A missing token or a rejected token (401 - expired/invalid)
    // instantly clears the session and sends the admin back to
    // admin_login.html. 403 is deliberately NOT handled the same
    // way anymore: it used to mean only "wrong role" (requireRole),
    // but now that this dashboard can trigger WEVA's own BLOCK
    // mitigation on purpose (see the Simulate Attack demo below),
    // 403 just as often means "this device is temporarily
    // rate-limited by the system you're demonstrating" - an
    // expected, informative outcome, not a reason to force a
    // logout mid-demo. It's returned as-is, same as 400/429/
    // success, so the caller (submitAction/showResult, or the
    // demo's own status line) can read and show the server's real
    // message.
    async function authFetch(path, options = {}) {
        const token = localStorage.getItem('authToken');

        if (!token) {
            goToLogin();
            return new Promise(() => {}); // navigation is already underway
        }

        const deviceId = await getDeviceFingerprint();

        const response = await fetch(`${API_BASE}${path}`, {
            ...options,
            headers: {
                ...(options.headers || {}),
                'Authorization': `Bearer ${token}`,
                'x-device-id': deviceId
            }
        });

        if (response.status === 401) {
            goToLogin();
            return new Promise(() => {});
        }

        return response;
    }

    // Runs an authFetch() call and parses its JSON body, converting
    // a network/connection failure into the same {success, message}
    // shape every real server response already uses - so callers
    // only ever need to handle one case instead of a try/catch on
    // top of every button handler.
    async function submitAction(path, options) {
        try {
            const response = await authFetch(path, options);
            return await response.json();
        } catch (error) {
            return { success: false, message: 'Cannot connect to the server. Please try again.' };
        }
    }

    // Every route this dashboard talks to returns {success,
    // message} - on success AND on failure - so one tiny helper
    // covers all of them.
    function showResult(data) {
        alert((data && data.message) ? data.message : 'Something went wrong.');
    }

    // fetchLogs() lives up here (not inside the SECURITY LOGS try
    // block below) so it's in scope for both the sidebar nav's
    // "switched to Security & Logs -> refresh" call and the
    // refresh button's listener, without relying on it ever being
    // attached to `window` - see the SECURITY LOGS section for why
    // that matters.
    async function fetchLogs() {
        const tableBody = document.getElementById('logsTableBody');
        try {
            const response = await authFetch('/api/admin/logs');
            const data = await response.json();

            if (data.success) {
                tableBody.innerHTML = '';
                data.logs.forEach(log => {
                    let badgeClass = 'bg-info';
                    if (log.event_type.includes('SUCCESS') || log.description.includes('ALLOW')) badgeClass = 'bg-success';
                    else if (log.event_type.includes('FAILED') || log.description.includes('THROTTLE')) badgeClass = 'bg-warning';
                    else if (log.description.includes('BLOCK')) badgeClass = 'bg-danger';

                    tableBody.innerHTML += `
                        <tr>
                            <td style="color: #888;">${escapeHtml(log.formatted_time)}</td>
                            <td><strong>${escapeHtml(log.user_email)}</strong></td>
                            <td><span class="badge ${badgeClass}">${escapeHtml(log.event_type)}</span></td>
                            <td>${renderLogDescription(log.description)}</td>
                        </tr>
                    `;
                });
            } else {
                tableBody.innerHTML = `<tr><td colspan="4" style="color: red;">${escapeHtml(data.message || 'Could not load logs.')}</td></tr>`;
            }
        } catch (error) {
            console.error('[admin_dashboard] fetchLogs() failed:', error);
            tableBody.innerHTML = '<tr><td colspan="4" style="color: red;">Cannot connect to Database.</td></tr>';
        }
    }

    // Same reasoning as fetchLogs() above for living up here rather
    // than inside the BLOCKED DEVICES try block below: the sidebar nav
    // handler calls this when Admin Settings is opened, so it needs to
    // be in scope there too.
    //
    // Builds each row via document.createElement + a real DOM property
    // assignment for the device identifier (row.dataset.identifier =
    // ...), NOT by interpolating it into the innerHTML template string.
    // That distinction matters here specifically: a device identifier
    // is core/monitor.js's deviceId, which traces back to the
    // client-supplied x-device-id header (see public/script.js's
    // getDeviceFingerprint()) - attacker-controlled input that's
    // already made it into the database via ipTracking. escapeHtml()
    // is safe for TEXT content but does not escape quote characters,
    // so embedding it inside a "..."-quoted HTML attribute could let a
    // crafted device id break out of the attribute. Setting it via the
    // DOM property instead sidesteps that whole class of bug rather
    // than trying to out-escape it.
    async function fetchBlockedDevices() {
        const tableBody = document.getElementById('blockedDevicesTableBody');
        if (!tableBody) return;
        try {
            const response = await authFetch('/api/admin/blocked-devices');
            const data = await response.json();

            if (!data.success) {
                tableBody.innerHTML = `<tr><td colspan="4" style="color: red;">${escapeHtml(data.message || 'Could not load blocked devices.')}</td></tr>`;
                return;
            }

            tableBody.innerHTML = '';
            if (data.devices.length === 0) {
                tableBody.innerHTML = '<tr><td colspan="4" class="text-muted">No devices are currently blocked.</td></tr>';
                return;
            }

            data.devices.forEach(device => {
                const row = document.createElement('tr');
                row.dataset.identifier = device.ipAddress;
                const blockedUntilText = device.blockedUntil ? new Date(device.blockedUntil).toLocaleString() : '—';
                row.innerHTML = `
                    <td><strong>${escapeHtml(device.ipAddress)}</strong></td>
                    <td>${escapeHtml(blockedUntilText)}</td>
                    <td>${escapeHtml(String(device.totalRequests))}</td>
                    <td><button class="btn-text btn-text--danger" data-action="revoke"><i class="fa-solid fa-unlock"></i> Force Logout / Revoke</button></td>
                `;
                tableBody.appendChild(row);
            });
        } catch (error) {
            console.error('[admin_dashboard] fetchBlockedDevices() failed:', error);
            tableBody.innerHTML = '<tr><td colspan="4" style="color: red;">Cannot connect to server.</td></tr>';
        }
    }

    console.log('[admin_dashboard] Helpers defined.');

    // =============================================================
    // TOPBAR (Logout)
    // =============================================================
    try {
        console.log('[admin_dashboard] Wiring topbar...');
        const btnLogout = document.getElementById('btnLogout');
        if (!btnLogout) throw new Error('#btnLogout not found in the DOM.');

        btnLogout.addEventListener('click', (e) => {
            e.preventDefault();
            goToLogin();
        });
        console.log('[admin_dashboard] Topbar wired successfully.');
    } catch (err) {
        console.error('[admin_dashboard] Topbar wiring FAILED:', err);
    }

    // =============================================================
    // SIDEBAR NAVIGATION
    // =============================================================
    try {
        console.log('[admin_dashboard] Wiring sidebar navigation...');
        const sidebarNav = document.getElementById('sidebar-nav');
        const mainTitle = document.getElementById('main-title');
        const sectionContainers = document.querySelectorAll('.section-container');

        if (!sidebarNav) throw new Error('#sidebar-nav not found in the DOM.');
        if (!mainTitle) throw new Error('#main-title not found in the DOM.');
        if (sectionContainers.length === 0) throw new Error('No .section-container elements found in the DOM.');

        sidebarNav.addEventListener('click', (e) => {
            const clickedLink = e.target.closest('li');
            if (!clickedLink) return;

            sidebarNav.querySelectorAll('li').forEach(li => li.classList.remove('active'));
            clickedLink.classList.add('active');

            sectionContainers.forEach(container => container.style.display = 'none');
            const targetSectionId = clickedLink.dataset.section;
            const targetSection = document.getElementById(targetSectionId);
            if (!targetSection) {
                console.error(`[admin_dashboard] Sidebar click: no element with id "${targetSectionId}" (from data-section) exists.`);
                return;
            }
            targetSection.style.display = 'block';

            mainTitle.innerText = clickedLink.innerText;

            if (targetSectionId === 'section-security-logs') {
                fetchLogs();
            } else if (targetSectionId === 'section-admin-settings') {
                fetchBlockedDevices();
            }
        });
        console.log(`[admin_dashboard] Sidebar navigation wired successfully (${sidebarNav.querySelectorAll('li').length} items, ${sectionContainers.length} sections).`);
    } catch (err) {
        console.error('[admin_dashboard] Sidebar navigation wiring FAILED:', err);
    }

    // =============================================================
    // LIVE ANOMALY CHART (WEVA Score Feed)
    // =============================================================
    try {
        console.log('[admin_dashboard] Wiring live anomaly chart...');
        const canvas = document.getElementById('anomalyChart');
        if (!canvas) throw new Error('#anomalyChart not found in the DOM.');
        const ctx = canvas.getContext('2d');

        // Threshold lines mirror config/securityConfig.js's actual
        // defaults (suspicious=25, critical/throttle=60, block=85) -
        // see core/decisionEngine.js for how they're applied.
        const THRESHOLDS = [
            { value: 25, label: 'LOG', color: '#b9660b' },
            { value: 60, label: 'THROTTLE', color: '#e0651e' },
            { value: 85, label: 'BLOCK', color: '#c62828' }
        ];
        const RISK_COLORS = { LOW: '#1e9e4a', MEDIUM: '#d99a1b', HIGH: '#e0651e', CRITICAL: '#c62828' };

        let scoreHistory = [];

        // Sizes the canvas's actual pixel buffer to match its rendered
        // CSS size (times devicePixelRatio), so lines/text stay crisp
        // instead of blurring - a plain width/height HTML attribute
        // would render at a fixed resolution regardless of how large
        // the element actually displays.
        function resizeCanvas() {
            const dpr = window.devicePixelRatio || 1;
            const rect = canvas.getBoundingClientRect();
            canvas.width = Math.round(rect.width * dpr);
            canvas.height = Math.round(rect.height * dpr);
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        }

        function scoreToY(score, padding, plotH) {
            return padding.top + plotH - (Math.max(0, Math.min(100, score)) / 100) * plotH;
        }

        function drawChart() {
            const rect = canvas.getBoundingClientRect();
            const width = rect.width;
            const height = rect.height;
            const padding = { top: 14, right: 14, bottom: 10, left: 34 };
            const plotW = Math.max(0, width - padding.left - padding.right);
            const plotH = Math.max(0, height - padding.top - padding.bottom);

            ctx.clearRect(0, 0, width, height);

            ctx.fillStyle = '#8b909a';
            ctx.font = '11px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';
            ctx.textBaseline = 'middle';
            [0, 50, 100].forEach(v => ctx.fillText(String(v), 4, scoreToY(v, padding, plotH)));

            THRESHOLDS.forEach(t => {
                const y = scoreToY(t.value, padding, plotH);
                ctx.strokeStyle = t.color;
                ctx.setLineDash([5, 4]);
                ctx.lineWidth = 1;
                ctx.beginPath();
                ctx.moveTo(padding.left, y);
                ctx.lineTo(padding.left + plotW, y);
                ctx.stroke();
                ctx.setLineDash([]);
                ctx.fillStyle = t.color;
                ctx.textAlign = 'right';
                ctx.fillText(`${t.label} (${t.value})`, padding.left + plotW - 4, y - 8);
                ctx.textAlign = 'left';
            });

            if (scoreHistory.length === 0) {
                ctx.fillStyle = '#8b909a';
                ctx.textAlign = 'center';
                ctx.fillText('Waiting for activity - try "Simulate Attack" below.', padding.left + plotW / 2, padding.top + plotH / 2);
                ctx.textAlign = 'left';
                return;
            }

            const n = scoreHistory.length;
            const stepX = n > 1 ? plotW / (n - 1) : 0;
            const xFor = i => padding.left + (n > 1 ? i * stepX : plotW / 2);

            ctx.strokeStyle = '#8b0000';
            ctx.lineWidth = 2;
            ctx.beginPath();
            scoreHistory.forEach((point, i) => {
                const x = xFor(i);
                const y = scoreToY(point.score, padding, plotH);
                if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
            });
            ctx.stroke();

            scoreHistory.forEach((point, i) => {
                const x = xFor(i);
                const y = scoreToY(point.score, padding, plotH);
                ctx.beginPath();
                ctx.arc(x, y, 3.5, 0, Math.PI * 2);
                ctx.fillStyle = RISK_COLORS[point.riskLevel] || '#565b64';
                ctx.fill();
            });
        }

        // Deliberately hits authFetch(), not submitAction(): a failed
        // poll should stay silent (console only) rather than pop an
        // alert() every 1.5 seconds if the network hiccups.
        async function pollScores() {
            try {
                const response = await authFetch('/api/admin/scores');
                const data = await response.json();
                if (data.success) {
                    scoreHistory = data.scores;
                    drawChart();
                }
            } catch (err) {
                console.error('[admin_dashboard] Anomaly chart poll failed:', err);
            }
        }

        resizeCanvas();
        drawChart();
        pollScores();
        setInterval(pollScores, 1500);
        window.addEventListener('resize', () => { resizeCanvas(); drawChart(); });

        console.log('[admin_dashboard] Live anomaly chart wired successfully.');
    } catch (err) {
        console.error('[admin_dashboard] Live anomaly chart wiring FAILED:', err);
    }

    // =============================================================
    // DEMO MODE (Simulate Attack)
    // =============================================================
    try {
        console.log('[admin_dashboard] Wiring demo attack simulation...');
        const btnSimulateAttack = document.getElementById('btnSimulateAttack');
        const demoStatus = document.getElementById('demoStatus');
        if (!btnSimulateAttack) throw new Error('#btnSimulateAttack not found in the DOM.');
        if (!demoStatus) throw new Error('#demoStatus not found in the DOM.');

        function wait(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        }

        // Fires one POST /api/demo/ping (same authMiddleware ->
        // requireRole('admin') -> securityMiddleware chain as every
        // real action) and resolves to its HTTP status, never
        // throwing - one failed ping should never stop the rest of
        // the burst.
        async function sendPing() {
            try {
                const response = await authFetch('/api/demo/ping', { method: 'POST' });
                return response.status;
            } catch (err) {
                return 0;
            }
        }

        btnSimulateAttack.addEventListener('click', async () => {
            btnSimulateAttack.disabled = true;
            btnSimulateAttack.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Simulating...';
            demoStatus.textContent = 'Sending an escalating burst through the WEVA pipeline...';

            try {
                // Stage 1: a handful of pings spaced 120ms apart, purely
                // so the chart shows one clean, isolated LOG-level flag
                // before the spike - narratable on its own ("here's a
                // mild anomaly").
                for (let i = 0; i < 4; i++) {
                    sendPing();
                    await wait(120);
                }

                // Stage 2: a genuinely CONCURRENT burst - every ping
                // fired in the same tick via Promise.all, not spaced
                // out one at a time. This isn't just style: an earlier
                // version of this feature spaced every ping out with a
                // shrinking-but-still-real gap, and testing it against
                // the real server showed the score climbing for a few
                // requests and then plateauing and *falling* - because
                // core/profiler.js's EMA baseline (alpha=0.1) updates on
                // every single request and adapts toward whatever rate
                // it observes, so a long, evenly-paced burst gives it
                // just enough time to "learn" the elevated pace as the
                // new normal before the score can climb far, exactly as
                // an adaptive baseline should for genuinely sustained
                // behavior. A short, truly simultaneous spike outruns
                // that adaptation instead of feeding it: Node still
                // processes each of these one at a time internally, so
                // the score climbs through MEDIUM/HIGH as the batch is
                // worked through and crosses BLOCK before the baseline
                // gets enough update cycles to catch up.
                //
                // 50 pings, not fewer: dispatch concurrency has real
                // run-to-run variance (connection pooling, OS/browser
                // scheduling - confirmed empirically while building
                // this, where identical code sometimes reached BLOCK
                // with room to spare and sometimes fell just short at a
                // smaller batch size), so this number carries a
                // deliberate safety margin for a live, one-shot demo
                // rather than the bare minimum that worked once.
                const pending = Array.from({ length: 50 }, () => sendPing());
                const statuses = await Promise.all(pending);

                if (statuses.includes(403)) {
                    demoStatus.innerHTML = '<strong style="color:#c62828;">BLOCKED.</strong> WEVA scored this device past the BLOCK threshold - other admin actions will be rejected for about 60 seconds while the temporary lockout is active. Watch the chart above.';
                } else if (statuses.includes(429)) {
                    demoStatus.innerHTML = '<strong style="color:#b9660b;">THROTTLED.</strong> WEVA flagged elevated velocity. Check the chart above.';
                } else {
                    demoStatus.textContent = 'Burst complete - check the chart above for the resulting scores.';
                }
            } catch (err) {
                console.error('[admin_dashboard] Simulate Attack failed:', err);
                demoStatus.textContent = 'Something went wrong sending the burst - see console.';
            } finally {
                btnSimulateAttack.disabled = false;
                btnSimulateAttack.innerHTML = '<i class="fa-solid fa-bolt"></i> Simulate Attack';
            }
        });

        console.log('[admin_dashboard] Demo attack simulation wired successfully.');
    } catch (err) {
        console.error('[admin_dashboard] Demo attack simulation wiring FAILED:', err);
    }

    // =============================================================
    // SECURITY LOGS
    // =============================================================
    try {
        console.log('[admin_dashboard] Wiring security logs (refresh button + initial fetch)...');
        const btnRefreshLogs = document.getElementById('btnRefreshLogs');
        if (!btnRefreshLogs) throw new Error('#btnRefreshLogs not found in the DOM.');

        btnRefreshLogs.addEventListener('click', fetchLogs);
        fetchLogs();
        console.log('[admin_dashboard] Security logs wired successfully; initial fetchLogs() triggered.');
    } catch (err) {
        console.error('[admin_dashboard] Security logs wiring FAILED:', err);
    }

    // =============================================================
    // PRINTABLE AUDIT REPORT
    // =============================================================
    // Fulfils a Non-Functional Requirement (business/compliance
    // reporting), not a feature request in the functional sense - the
    // system needs to be able to hand an auditor a static, dated
    // artifact, not just a live dashboard. window.print() (with the
    // browser's own "Save as PDF" option) is a native capability;
    // style.css's @media print block does the actual formatting, this
    // just stamps a real generation timestamp before invoking it.
    try {
        console.log('[admin_dashboard] Wiring printable audit report...');
        const btnGenerateReport = document.getElementById('btnGenerateReport');
        const reportTimestamp = document.getElementById('reportTimestamp');
        if (!btnGenerateReport) throw new Error('#btnGenerateReport not found in the DOM.');

        btnGenerateReport.addEventListener('click', () => {
            if (reportTimestamp) {
                reportTimestamp.textContent = new Date().toLocaleString();
            }
            window.print();
        });
        console.log('[admin_dashboard] Printable audit report wired successfully.');
    } catch (err) {
        console.error('[admin_dashboard] Printable audit report wiring FAILED:', err);
    }

    // =============================================================
    // BLOCKED DEVICES PANEL (Priority #5: persistent mitigation)
    // =============================================================
    try {
        console.log('[admin_dashboard] Wiring Blocked Devices panel...');
        const btnRefreshBlockedDevices = document.getElementById('btnRefreshBlockedDevices');
        const blockedDevicesTableBody = document.getElementById('blockedDevicesTableBody');
        if (!btnRefreshBlockedDevices) throw new Error('#btnRefreshBlockedDevices not found in the DOM.');
        if (!blockedDevicesTableBody) throw new Error('#blockedDevicesTableBody not found in the DOM.');

        btnRefreshBlockedDevices.addEventListener('click', fetchBlockedDevices);

        // Delegated listener (same pattern as the Student/Subject CRUD
        // tables above): handles every row's Force Logout / Revoke
        // button, including rows rendered by a later refresh.
        blockedDevicesTableBody.addEventListener('click', async (e) => {
            const btn = e.target.closest('button[data-action="revoke"]');
            if (!btn) return;

            const row = btn.closest('tr');
            const identifier = row.dataset.identifier;
            if (!confirm(`Force logout and unblock "${identifier}"?\n\nThis lifts the WEVA block immediately and ends the session of whichever user this device was most recently seen as, if any.`)) return;

            const data = await submitAction('/api/admin/blocked-devices/unblock', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ identifier })
            });
            showResult(data);
            if (data.success) fetchBlockedDevices();
        });

        console.log('[admin_dashboard] Blocked Devices panel wired successfully.');
    } catch (err) {
        console.error('[admin_dashboard] Blocked Devices panel wiring FAILED:', err);
    }

    // =============================================================
    // DATABASE BACKUP (real, working Disaster Recovery export)
    // =============================================================
    // Hits GET /api/admin/backup (server.js), which exports every table
    // this schema currently models - see that route's own comment for
    // exactly what is and isn't included, and why (students/subjects/
    // grades don't exist as persisted records yet; passwordHash and the
    // Session table are deliberately excluded on security grounds, not
    // technical ones). Everything below is pure client-side file
    // handling: a Blob + a programmatically-clicked, immediately-
    // revoked <a download> is the standard vanilla-JS way to trigger a
    // browser download from fetched data - no library needed.
    try {
        console.log('[admin_dashboard] Wiring database backup...');
        const btnBackupDatabase = document.getElementById('btnBackupDatabase');
        if (!btnBackupDatabase) throw new Error('#btnBackupDatabase not found in the DOM.');

        btnBackupDatabase.addEventListener('click', async () => {
            btnBackupDatabase.disabled = true;
            btnBackupDatabase.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Backing up...';
            console.log('[admin_dashboard] Backup requested - fetching /api/admin/backup...');

            try {
                const data = await submitAction('/api/admin/backup');

                if (!data.success) {
                    showResult(data);
                    return;
                }

                const filename = `sis_database_backup_${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);

                const link = document.createElement('a');
                link.href = url;
                link.download = filename;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                URL.revokeObjectURL(url);

                console.log(`[admin_dashboard] Backup downloaded as ${filename}.`);
                alert(`Backup downloaded: ${filename}`);
            } catch (err) {
                console.error('[admin_dashboard] Database backup failed:', err);
                alert('Backup failed - could not reach the server. See console for details.');
            } finally {
                btnBackupDatabase.disabled = false;
                btnBackupDatabase.innerHTML = '<i class="fa-solid fa-database"></i> Backup PostgreSQL DB';
            }
        });

        console.log('[admin_dashboard] Database backup wired successfully.');
    } catch (err) {
        console.error('[admin_dashboard] Database backup wiring FAILED:', err);
    }

    // =============================================================
    // STUDENT RECORDS CRUD
    // =============================================================
    try {
        console.log('[admin_dashboard] Wiring Student Records CRUD...');
        const studentsTableBody = document.getElementById('studentsTableBody');
        const btnAddStudent = document.getElementById('btnAddStudent');
        if (!studentsTableBody) throw new Error('#studentsTableBody not found in the DOM.');
        if (!btnAddStudent) throw new Error('#btnAddStudent not found in the DOM.');

        function studentRowHtml({ studentId, fullName, department, program, yearLevel, status }) {
            return `
                <td><strong>${escapeHtml(studentId)}</strong></td>
                <td>${escapeHtml(fullName)}</td>
                <td>${escapeHtml(department)}</td>
                <td>${escapeHtml(program)}</td>
                <td>${escapeHtml(yearLevel)}</td>
                <td><span class="badge bg-success">${escapeHtml(status)}</span></td>
                <td><div class="table-actions"><button class="btn-text" data-action="edit"><i class="fa-solid fa-pen"></i> Edit</button><button class="btn-text btn-text--danger" data-action="remove"><i class="fa-solid fa-trash-can"></i> Remove</button></div></td>
            `;
        }

        btnAddStudent.addEventListener('click', async () => {
            const studentId = prompt('Student ID (e.g. A23-00001):');
            if (studentId === null) return;
            if (!studentId.trim()) { alert('Student ID is required.'); return; }

            const fullName = prompt('Full Name:');
            if (fullName === null) return;
            if (!fullName.trim()) { alert('Full Name is required.'); return; }

            const department = prompt('Department (e.g. CCMS):', '') || '';
            const program = prompt('Program (e.g. BSCS - SoftEng):', '') || '';
            const yearLevel = prompt('Year Level (e.g. 1st Year):', '') || '';

            // Hits the placeholder POST /api/students route added
            // in server.js, gated by authMiddleware ->
            // requireRole('admin') -> securityMiddleware, same as
            // every other action below.
            const data = await submitAction('/api/students', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ studentId, fullName, department, program, yearLevel })
            });
            showResult(data);
            if (!data.success) return;

            // The endpoint is a placeholder (no Student table
            // exists yet - see server.js), so there is nothing to
            // re-fetch from. This appends the row locally so the UI
            // still feels responsive; it will not survive a page
            // reload until real persistence exists.
            const row = document.createElement('tr');
            row.dataset.id = studentId;
            row.innerHTML = studentRowHtml({ studentId, fullName, department, program, yearLevel, status: 'ENROLLED' });
            studentsTableBody.appendChild(row);
        });

        // One delegated listener handles every row's Edit/Remove
        // buttons - including rows added after page load - the
        // same pattern the sidebar nav above already uses.
        studentsTableBody.addEventListener('click', async (e) => {
            const btn = e.target.closest('button[data-action]');
            if (!btn) return;

            const row = btn.closest('tr');
            const id = row.dataset.id;
            const cells = row.children;

            if (btn.dataset.action === 'edit') {
                const fullName = prompt('Full Name:', cells[1].innerText);
                if (fullName === null) return;
                const department = prompt('Department:', cells[2].innerText);
                if (department === null) return;
                const program = prompt('Program:', cells[3].innerText);
                if (program === null) return;
                const yearLevel = prompt('Year Level:', cells[4].innerText);
                if (yearLevel === null) return;

                const data = await submitAction(`/api/students/${encodeURIComponent(id)}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ fullName, department, program, yearLevel })
                });
                showResult(data);
                if (!data.success) return;

                cells[1].innerText = fullName;
                cells[2].innerText = department;
                cells[3].innerText = program;
                cells[4].innerText = yearLevel;

            } else if (btn.dataset.action === 'remove') {
                if (!confirm('Are you sure you want to delete this record?')) return;

                const data = await submitAction(`/api/students/${encodeURIComponent(id)}`, { method: 'DELETE' });
                showResult(data);
                if (data.success) row.remove();
            }
        });
        console.log('[admin_dashboard] Student Records CRUD wired successfully.');
    } catch (err) {
        console.error('[admin_dashboard] Student Records CRUD wiring FAILED:', err);
    }

    // =============================================================
    // SUBJECT MANAGEMENT CRUD (mirrors Student Records above exactly)
    // =============================================================
    try {
        console.log('[admin_dashboard] Wiring Subject Management CRUD...');
        const subjectsTableBody = document.getElementById('subjectsTableBody');
        const btnAddSubject = document.getElementById('btnAddSubject');
        if (!subjectsTableBody) throw new Error('#subjectsTableBody not found in the DOM.');
        if (!btnAddSubject) throw new Error('#btnAddSubject not found in the DOM.');

        function subjectRowHtml({ subjectCode, subjectTitle, units, department }) {
            return `
                <td><strong>${escapeHtml(subjectCode)}</strong></td>
                <td>${escapeHtml(subjectTitle)}</td>
                <td>${escapeHtml(units)}</td>
                <td>${escapeHtml(department)}</td>
                <td><div class="table-actions"><button class="btn-text" data-action="edit"><i class="fa-solid fa-pen"></i> Edit</button><button class="btn-text btn-text--danger" data-action="remove"><i class="fa-solid fa-trash-can"></i> Remove</button></div></td>
            `;
        }

        btnAddSubject.addEventListener('click', async () => {
            const subjectCode = prompt('Subject Code (e.g. SE301):');
            if (subjectCode === null) return;
            if (!subjectCode.trim()) { alert('Subject Code is required.'); return; }

            const subjectTitle = prompt('Subject Title:');
            if (subjectTitle === null) return;
            if (!subjectTitle.trim()) { alert('Subject Title is required.'); return; }

            const units = prompt('Units:', '3') || '';
            const department = prompt('Department (e.g. CCMS):', '') || '';

            const data = await submitAction('/api/subjects', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ subjectCode, subjectTitle, units, department })
            });
            showResult(data);
            if (!data.success) return;

            const row = document.createElement('tr');
            row.dataset.id = subjectCode;
            row.innerHTML = subjectRowHtml({ subjectCode, subjectTitle, units, department });
            subjectsTableBody.appendChild(row);
        });

        subjectsTableBody.addEventListener('click', async (e) => {
            const btn = e.target.closest('button[data-action]');
            if (!btn) return;

            const row = btn.closest('tr');
            const id = row.dataset.id;
            const cells = row.children;

            if (btn.dataset.action === 'edit') {
                const subjectTitle = prompt('Subject Title:', cells[1].innerText);
                if (subjectTitle === null) return;
                const units = prompt('Units:', cells[2].innerText);
                if (units === null) return;
                const department = prompt('Department:', cells[3].innerText);
                if (department === null) return;

                const data = await submitAction(`/api/subjects/${encodeURIComponent(id)}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ subjectTitle, units, department })
                });
                showResult(data);
                if (!data.success) return;

                cells[1].innerText = subjectTitle;
                cells[2].innerText = units;
                cells[3].innerText = department;

            } else if (btn.dataset.action === 'remove') {
                if (!confirm('Are you sure you want to delete this record?')) return;

                const data = await submitAction(`/api/subjects/${encodeURIComponent(id)}`, { method: 'DELETE' });
                showResult(data);
                if (data.success) row.remove();
            }
        });
        console.log('[admin_dashboard] Subject Management CRUD wired successfully.');
    } catch (err) {
        console.error('[admin_dashboard] Subject Management CRUD wiring FAILED:', err);
    }

    console.log('[admin_dashboard] Initialization complete.');
});
