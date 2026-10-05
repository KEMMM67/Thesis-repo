// =============================================================
// ROUTE GUARD (runs immediately - before any DOM wiring below)
// =============================================================
// A static HTML file has no gate of its own: unlike an API route,
// nothing stops a browser from requesting student_dashboard.html
// directly without ever logging in. This check is therefore the
// first thing this script does, so an unauthenticated visitor is
// sent back to the Student login immediately rather than being left
// looking at dashboard content.
//
// This used to be defense-in-depth / UX only, layered on top of
// entirely static placeholder content. It is now backed by a real
// server-side boundary too: every value this page displays is fetched
// from GET /api/students/me (server.js), which independently requires
// authMiddleware and returns 401 with no token regardless of what this
// check does - see loadDashboardData() below.
//
// The session lives under the Student Portal's own localStorage keys,
// written by public/script.js at login. Both portals share one origin, so
// one localStorage; separate keys are what let a student and an admin be
// signed in on the same browser without one replacing the other's token.
const STUDENT_SESSION = { token: 'sis.student.token', email: 'sis.student.email' };

if (!localStorage.getItem(STUDENT_SESSION.token)) {
    window.location.replace('index.html');
} else {
    console.log('[student_dashboard] Script parsed. Waiting for DOMContentLoaded...');

    document.addEventListener('DOMContentLoaded', () => {
    console.log('[student_dashboard] DOMContentLoaded fired. Beginning initialization.');

    // =============================================================
    // CONFIG + SHARED HELPERS
    // =============================================================
    // Same origin that served this page: Express serves both the frontend and the API.
    const API_BASE = window.location.origin;

    /**
     * Escapes text for safe insertion into innerHTML. Applied to every
     * fetched value rendered into a table below, even though it
     * ultimately comes from this student's own account - defense in
     * depth, and consistent with public/admin_dashboard.js#escapeHtml.
     *
     * @param {*} str - Value to escape.
     * @returns {string} HTML-escaped string.
     */
    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str == null ? '' : String(str);
        return div.innerHTML;
    }

    /**
     * Formats a number as Philippine-peso currency (e.g. "₱18,500.00").
     *
     * @param {number} amount - Value to format.
     * @returns {string} Formatted currency string.
     */
    function formatCurrency(amount) {
        const value = Number(amount) || 0;
        return '₱' + value.toLocaleString('en-PH', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    }

    /**
     * Derives the same per-device fingerprint as public/script.js and
     * public/admin_dashboard.js. Duplicated rather than imported, since
     * this page is self-contained - consistent with the same choice
     * made in admin_dashboard.js.
     *
     * @returns {Promise<string>} Device identifier, prefixed "DEV-".
     */
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

    /**
     * Clears the stored session and redirects to the Student login page.
     * Used on a missing/expired session, mirroring goToLogin() in
     * public/admin_dashboard.js.
     *
     * @returns {void}
     */
    function goToLogin() {
        localStorage.removeItem(STUDENT_SESSION.token);
        localStorage.removeItem(STUDENT_SESSION.email);
        window.location.href = 'index.html';
    }

    /**
     * Wraps `fetch()` for authMiddleware-protected routes, attaching the
     * bearer token and device telemetry, and centralizing session-expiry
     * handling - mirrors authFetch() in public/admin_dashboard.js.
     *
     * @param {string} path - API path relative to API_BASE.
     * @param {RequestInit} [options] - Additional fetch options.
     * @returns {Promise<Response>}
     */
    async function authFetch(path, options = {}) {
        const token = localStorage.getItem(STUDENT_SESSION.token);

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

    console.log('[student_dashboard] Helpers defined.');

    // =============================================================
    // SIDEBAR NAVIGATION (section switching)
    // =============================================================
    try {
        console.log('[student_dashboard] Wiring sidebar navigation...');
        const sidebarNav = document.getElementById('sidebar-nav');
        const mainTitle = document.getElementById('main-title');
        const sectionContainers = document.querySelectorAll('.section-container');
        if (!sidebarNav) throw new Error('#sidebar-nav not found in the DOM.');

        sidebarNav.addEventListener('click', (e) => {
            const clickedItem = e.target.closest('li');
            if (!clickedItem) return;

            sidebarNav.querySelectorAll('li').forEach(li => li.classList.remove('active'));
            clickedItem.classList.add('active');

            sectionContainers.forEach(container => container.style.display = 'none');
            const targetSectionId = clickedItem.dataset.section;
            document.getElementById(targetSectionId).style.display = 'block';

            mainTitle.innerText = clickedItem.innerText;
        });
        console.log('[student_dashboard] Sidebar navigation wired successfully.');
    } catch (err) {
        console.error('[student_dashboard] Failed to wire sidebar navigation:', err.message);
    }

    // =============================================================
    // PRINTABLE GRADES REPORT
    // =============================================================
    // Mirrors #btnGenerateReport in public/admin_dashboard.js: window.print()
    // is a native browser capability, and style.css's @media print block
    // does the formatting - hiding page chrome and printing only whichever
    // .section-container is currently visible.
    try {
        console.log('[student_dashboard] Wiring printable grades report...');
        const btnPrintGrades = document.getElementById('btnPrintGrades');
        if (!btnPrintGrades) throw new Error('#btnPrintGrades not found in the DOM.');

        btnPrintGrades.addEventListener('click', () => window.print());
        console.log('[student_dashboard] Printable grades report wired successfully.');
    } catch (err) {
        console.error('[student_dashboard] Failed to wire printable grades report:', err.message);
    }

    // =============================================================
    // LOGOUT
    // =============================================================
    // Ends the session on the server first (POST /api/logout deletes its
    // Session row, so the token stops working everywhere at once), then
    // clears this browser's copy and follows the link back to the login
    // page. Clearing localStorage alone - all this used to do - left the
    // session valid for up to an hour for anyone holding a copy of the
    // token. If the server cannot be reached (5 s timeout), the browser
    // still signs out; the session then expires on its own schedule.
    try {
        console.log('[student_dashboard] Wiring logout...');
        const btnLogout = document.getElementById('btnLogout');
        if (!btnLogout) throw new Error('#btnLogout not found in the DOM.');

        btnLogout.addEventListener('click', async (event) => {
            event.preventDefault();
            const token = localStorage.getItem(STUDENT_SESSION.token);
            if (token) {
                try {
                    await fetch(`${API_BASE}/api/logout`, {
                        method: 'POST',
                        headers: { 'Authorization': `Bearer ${token}` },
                        signal: AbortSignal.timeout(5000)
                    });
                } catch (err) {
                    console.warn('[student_dashboard] Server-side logout failed; signing out locally anyway:', err);
                }
            }
            localStorage.removeItem(STUDENT_SESSION.token);
            localStorage.removeItem(STUDENT_SESSION.email);
            window.location.href = btnLogout.getAttribute('href') || 'index.html';
        });
        console.log('[student_dashboard] Logout wired successfully.');
    } catch (err) {
        console.error('[student_dashboard] Failed to wire logout:', err.message);
    }

    // =============================================================
    // DASHBOARD DATA (fetched from the authenticated API, replacing
    // what used to be hardcoded directly into student_dashboard.html)
    // =============================================================
    /**
     * Populates the Profile section and the topbar name from a
     * GET /api/students/me response.
     *
     * @param {object} data - Parsed response body.
     * @returns {void}
     */
    function renderProfile(data) {
        const { profile, stats, billing, clearance } = data;
        const fullyCleared = clearance.every(row => row.status === 'Cleared');

        document.getElementById('topbarUserName').textContent = profile.fullName;
        document.getElementById('profileFullName').textContent = profile.fullName;
        document.getElementById('profileSummary').textContent =
            `Student ID: ${profile.studentId} · ${profile.program} · ${profile.yearLevel}`;

        const badge = document.getElementById('profileStatusBadge');
        badge.textContent = profile.status;
        badge.className = 'badge ' + (profile.status === 'ENROLLED' ? 'bg-success' : 'bg-warning');

        document.getElementById('statEnrolledUnits').textContent = stats.enrolledUnits;
        document.getElementById('statGwa').textContent = stats.gwa != null ? stats.gwa.toFixed(2) : '—';
        document.getElementById('statBalance').textContent = formatCurrency(billing.balanceDue);
        document.getElementById('statClearance').textContent = fullyCleared ? 'Cleared' : 'Pending';

        const rows = [
            ['Full Name', profile.fullName],
            ['Student ID', profile.studentId],
            ['Program', profile.program],
            ['Year Level', profile.yearLevel],
            ['Department', profile.department],
            ['Email Address', profile.email]
        ];
        document.getElementById('profileInfoTableBody').innerHTML = rows
            .map(([label, value]) => `<tr><td><strong>${escapeHtml(label)}</strong></td><td>${escapeHtml(value)}</td></tr>`)
            .join('');
    }

    /**
     * Populates the Class Schedule section. Schedule has no backing
     * persistence model yet (see the route comment on GET /api/students/me
     * in server.js), so this renders whatever fixed placeholder rows the
     * API returns - real once that subsystem exists, but already served
     * only to an authenticated request either way.
     *
     * @param {object} data - Parsed response body.
     * @returns {void}
     */
    function renderSchedule(data) {
        document.getElementById('scheduleTitle').textContent = `Class Schedule (${data.currentTerm})`;

        const body = document.getElementById('scheduleTableBody');
        if (!data.schedule.length) {
            body.innerHTML = '<tr><td colspan="6">No schedule on file.</td></tr>';
            return;
        }

        body.innerHTML = data.schedule.map(row => `
            <tr>
                <td><strong>${escapeHtml(row.subjectCode)}</strong></td>
                <td>${escapeHtml(row.subjectTitle)}</td>
                <td>${escapeHtml(row.units)}</td>
                <td>${escapeHtml(row.schedule)}</td>
                <td>${escapeHtml(row.room)}</td>
                <td>${escapeHtml(row.instructor)}</td>
            </tr>
        `).join('');
    }

    /**
     * Same rule as public/admin_dashboard.js's grade report, so a "Failed"
     * remark reads as a failure here too instead of a green badge.
     *
     * @param {string|null} remarks - e.g. "Passed" or "Failed".
     * @returns {string} Badge class for the remarks.
     */
    function remarksBadgeClass(remarks) {
        if (/fail/i.test(remarks || '')) return 'bg-danger';
        if (/pass/i.test(remarks || '')) return 'bg-success';
        return 'bg-info';
    }

    /**
     * Populates the Grades Evaluation section from real Grade/Subject rows.
     *
     * @param {object} data - Parsed response body.
     * @returns {void}
     */
    function renderGrades(data) {
        const { grades, stats } = data;

        document.getElementById('gradesGwa').textContent = stats.gwa != null ? stats.gwa.toFixed(2) : '—';
        document.getElementById('gradesStanding').textContent = stats.academicStanding;

        const terms = [...new Set(grades.map(g => g.term).filter(Boolean))];
        const termFilter = document.getElementById('gradesTermFilter');
        termFilter.innerHTML = terms.length
            ? terms.map(t => `<option>${escapeHtml(t)}</option>`).join('')
            : '<option>No Term on File</option>';

        const body = document.getElementById('gradesTableBody');
        if (!grades.length) {
            body.innerHTML = '<tr><td colspan="5">No grades on file yet.</td></tr>';
            return;
        }

        body.innerHTML = grades.map(g => `
            <tr>
                <td><strong>${escapeHtml(g.subjectCode)}</strong></td>
                <td>${escapeHtml(g.subjectTitle)}</td>
                <td>${escapeHtml(g.units)}</td>
                <td>${g.grade != null ? escapeHtml(g.grade.toFixed(2)) : '—'}</td>
                <td><span class="badge ${remarksBadgeClass(g.remarks)}">${escapeHtml(g.remarks || '—')}</span></td>
            </tr>
        `).join('');
    }

    /**
     * Populates the Account/Billing Assessment section. Like Schedule,
     * this has no backing persistence model yet - see the route comment
     * on GET /api/students/me in server.js.
     *
     * @param {object} data - Parsed response body.
     * @returns {void}
     */
    function renderBilling(data) {
        const { billing } = data;

        document.getElementById('billingBalance').textContent = formatCurrency(billing.balanceDue);
        document.getElementById('billingStatusText').textContent = billing.status;
        document.getElementById('billingFeesTitle').textContent = `Assessment of Fees (${data.currentTerm})`;

        const feesBody = document.getElementById('billingFeesTableBody');
        const totalAssessment = billing.fees.reduce((sum, fee) => sum + Number(fee.amount || 0), 0);
        feesBody.innerHTML = billing.fees
            .map(fee => `<tr><td>${escapeHtml(fee.type)}</td><td>${formatCurrency(fee.amount).slice(1)}</td></tr>`)
            .join('') + `<tr><td><strong>Total Assessment</strong></td><td><strong>${formatCurrency(totalAssessment).slice(1)}</strong></td></tr>`;

        const paymentsBody = document.getElementById('billingPaymentsTableBody');
        paymentsBody.innerHTML = billing.payments.length
            ? billing.payments.map(p => `
                <tr>
                    <td>${escapeHtml(p.date)}</td>
                    <td>${escapeHtml(p.orNumber)}</td>
                    <td>${formatCurrency(p.amount).slice(1)}</td>
                    <td>${escapeHtml(p.description)}</td>
                </tr>
            `).join('')
            : '<tr><td colspan="4">No payments on file.</td></tr>';
    }

    /**
     * Populates the Clearance Status section. Like Schedule and Billing,
     * this has no backing persistence model yet - see the route comment
     * on GET /api/students/me in server.js.
     *
     * @param {object} data - Parsed response body.
     * @returns {void}
     */
    function renderClearance(data) {
        const body = document.getElementById('clearanceTableBody');
        body.innerHTML = data.clearance.length
            ? data.clearance.map(row => `
                <tr>
                    <td>${escapeHtml(row.requirement)}</td>
                    <td>${escapeHtml(row.office)}</td>
                    <td><span class="badge ${row.status === 'Cleared' ? 'bg-success' : 'bg-warning'}">${escapeHtml(row.status)}</span></td>
                </tr>
            `).join('')
            : '<tr><td colspan="3">No clearance records on file.</td></tr>';
    }

    /**
     * Fetches this student's dashboard data from the authenticated API and
     * renders every section. Each renderer runs in its own try/catch so a
     * problem in one section cannot blank out the rest of the page.
     *
     * @returns {Promise<void>}
     */
    async function loadDashboardData() {
        console.log('[student_dashboard] Loading dashboard data from /api/students/me...');
        try {
            const response = await authFetch('/api/students/me');
            const data = await response.json();

            if (!response.ok || !data.success) {
                document.getElementById('main-content').innerHTML =
                    `<div class="section-container" style="display:block;"><p>${escapeHtml(data.message || 'Could not load your dashboard.')}</p></div>`;
                console.error('[student_dashboard] /api/students/me returned an error:', data.message);
                return;
            }

            for (const [name, renderer] of [
                ['profile', renderProfile],
                ['schedule', renderSchedule],
                ['grades', renderGrades],
                ['billing', renderBilling],
                ['clearance', renderClearance]
            ]) {
                try {
                    renderer(data);
                } catch (err) {
                    console.error(`[student_dashboard] Failed to render ${name}:`, err.message);
                }
            }
            console.log('[student_dashboard] Dashboard data loaded and rendered.');
        } catch (err) {
            console.error('[student_dashboard] Failed to load dashboard data:', err.message);
        }
    }

    loadDashboardData();

    console.log('[student_dashboard] Initialization complete.');
    });
}
