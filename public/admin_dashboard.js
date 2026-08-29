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
    // A missing token, a rejected token (401 - expired/invalid),
    // and a rejected role or blocked device (403 - requireRole or
    // a BLOCK mitigation) are all treated identically: instantly
    // clear the session and send the admin back to
    // admin_login.html rather than leaving the page in a
    // half-authenticated state. Anything else - success, 400
    // validation errors, 429 THROTTLE - is returned as-is so the
    // caller can read the server's own {success, message} body.
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

        if (response.status === 401 || response.status === 403) {
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
                            <td>${escapeHtml(log.description)}</td>
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
            }
        });
        console.log(`[admin_dashboard] Sidebar navigation wired successfully (${sidebarNav.querySelectorAll('li').length} items, ${sectionContainers.length} sections).`);
    } catch (err) {
        console.error('[admin_dashboard] Sidebar navigation wiring FAILED:', err);
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
