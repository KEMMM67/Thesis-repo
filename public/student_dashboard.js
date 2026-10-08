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

    /** Where this browser's device ID is kept - the same key public/script.js and the admin pages use. */
    const DEVICE_ID_KEY = 'sis.deviceId';
    const DEVICE_ID_FORMAT = /^DEV-[0-9a-f]{32}$/;
    let pageDeviceId = null;

    /**
     * Returns this browser's random device ID, creating it on first use -
     * the same as getDeviceId() in public/script.js, which explains why it
     * is random rather than a browser fingerprint. Duplicated rather than
     * imported, since this page is self-contained - consistent with the
     * same choice made in admin_dashboard.js.
     *
     * @returns {string} "DEV-" and 32 hex digits.
     */
    function getDeviceId() {
        try {
            const stored = localStorage.getItem(DEVICE_ID_KEY);
            if (DEVICE_ID_FORMAT.test(stored)) return stored;
            const created = randomDeviceId();
            localStorage.setItem(DEVICE_ID_KEY, created);
            return created;
        } catch {
            // Storage blocked: keep one ID for the life of this page instead.
            if (!pageDeviceId) pageDeviceId = randomDeviceId();
            return pageDeviceId;
        }
    }

    /** @returns {string} "DEV-" and 128 random bits as 32 hex digits. */
    function randomDeviceId() {
        const bytes = crypto.getRandomValues(new Uint8Array(16));
        return 'DEV-' + Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
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

        const deviceId = getDeviceId();

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
    // NAVIGATION (sidebar, phone tab bar, "More" sheet, in-page links)
    // =============================================================
    // Every way of changing section - the desktop sidebar, the phone's
    // bottom tab bar, the "More" sheet, and shortcuts such as "View all" -
    // is a plain link to a hash (#grades, #account, ...) that also carries
    // a data-section attribute. The hash is the single source of truth: a
    // hashchange shows the matching .section-container. That also gives
    // the browser's Back button (and a phone's back gesture) a section-by-
    // section history, and lets a section open straight from a URL such
    // as student_dashboard.html#grades.
    //
    // Headings come from SECTIONS rather than from the clicked item's
    // text, so a label can differ between menus (the tab bar says
    // "Courses", the sidebar "My Courses") without changing the heading.
    const SECTIONS = {
        'section-home':      { hash: 'home',      title: 'Home',       subtitle: 'Here’s your semester at a glance.' },
        'section-courses':   { hash: 'courses',   title: 'My Courses', subtitle: 'The subjects you are enrolled in this term.' },
        'section-schedule':  { hash: 'schedule',  title: 'Schedule',   subtitle: 'Your weekly class timetable.' },
        'section-grades':    { hash: 'grades',    title: 'Grades',     subtitle: 'Final grades and your general weighted average.' },
        'section-billing':   { hash: 'account',   title: 'Account',    subtitle: 'Assessment of fees and payment history.' },
        'section-clearance': { hash: 'clearance', title: 'Clearance',  subtitle: 'Clearance status, office by office.' },
        'section-profile':   { hash: 'profile',   title: 'Profile',    subtitle: 'Your student record.' }
    };
    const HOME_SECTION = 'section-home';
    /** Sections a phone reaches through the "More" sheet, so the More tab lights up for them. */
    const MORE_SECTIONS = ['section-billing', 'section-clearance', 'section-profile'];
    /** Home's heading; renderProfile() replaces it with a greeting once the student's name is known. */
    let homeTitle = 'Welcome back';

    /**
     * Maps a location hash to its section id.
     *
     * @param {string} hash - e.g. "#grades".
     * @returns {string|null} The section id, or null for any other hash
     * (such as the skip link's #main-content), which navigation ignores.
     */
    function sectionForHash(hash) {
        const key = String(hash || '').replace(/^#/, '');
        return Object.keys(SECTIONS).find(id => SECTIONS[id].hash === key) || null;
    }

    /**
     * Shows one section and hides the others, then syncs every menu's
     * current item, the page heading and the document title.
     *
     * @param {string} sectionId - A key of SECTIONS.
     * @returns {void}
     */
    function showSection(sectionId) {
        const current = SECTIONS[sectionId] ? sectionId : HOME_SECTION;

        // Known sections only: the error message loadDashboardData() can
        // put in their place has no id, and must stay visible.
        document.querySelectorAll('.section-container').forEach(container => {
            if (SECTIONS[container.id]) container.hidden = container.id !== current;
        });

        document.querySelectorAll('.nav-item[data-section], .tab-item[data-section], .sheet__item[data-section]').forEach(item => {
            const isCurrent = item.dataset.section === current;
            item.classList.toggle('is-active', isCurrent);
            if (isCurrent) item.setAttribute('aria-current', 'page');
            else item.removeAttribute('aria-current');
        });

        const moreTab = document.getElementById('btnMore');
        if (moreTab) moreTab.classList.toggle('is-active', MORE_SECTIONS.includes(current));

        document.getElementById('main-title').textContent = current === HOME_SECTION ? homeTitle : SECTIONS[current].title;
        document.getElementById('main-subtitle').textContent = SECTIONS[current].subtitle;
        document.title = `${SECTIONS[current].title} | Student Portal`;
    }

    try {
        console.log('[student_dashboard] Wiring navigation...');
        const sidebarNav = document.getElementById('sidebar-nav');
        const moreSheet = document.getElementById('moreSheet');
        if (!sidebarNav) throw new Error('#sidebar-nav not found in the DOM.');

        document.addEventListener('click', (event) => {
            const sectionLink = event.target.closest('[data-section]');
            if (sectionLink) {
                if (moreSheet && moreSheet.open) moreSheet.close();
                // A link to the hash already showing fires no hashchange,
                // so show that section (and scroll back up) here instead.
                const target = SECTIONS[sectionLink.dataset.section];
                if (target && window.location.hash === `#${target.hash}`) {
                    event.preventDefault();
                    showSection(sectionLink.dataset.section);
                    window.scrollTo(0, 0);
                }
                return;
            }

            const actionButton = event.target.closest('[data-action]');
            if (!actionButton || !moreSheet) return;
            const action = actionButton.dataset.action;
            if (action === 'open-more') {
                moreSheet.showModal();
            } else if (action === 'close-sheet') {
                moreSheet.close();
            } else if (action === 'logout') {
                moreSheet.close();
                // The sidebar's #btnLogout carries the one wired sign-out
                // (see LOGOUT below), so the server-side logout runs here too.
                document.getElementById('btnLogout').click();
            }
        });

        // A click on the sheet's backdrop lands on the <dialog> itself;
        // everything inside the sheet sits in .sheet__body.
        if (moreSheet) {
            moreSheet.addEventListener('click', (event) => {
                if (event.target === moreSheet) moreSheet.close();
            });
        }

        window.addEventListener('hashchange', () => {
            const section = sectionForHash(window.location.hash);
            if (!section) return;
            showSection(section);
            window.scrollTo(0, 0);
        });

        showSection(sectionForHash(window.location.hash) || HOME_SECTION);
        console.log('[student_dashboard] Navigation wired successfully.');
    } catch (err) {
        console.error('[student_dashboard] Failed to wire navigation:', err.message);
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
    // Everything below only draws what GET /api/students/me returned.
    // Grades, units, GWA and standing are live records. The schedule,
    // billing and clearance rows are the route's fixed sample values, and
    // every panel that shows them keeps a visible "Sample" label.

    const DAY_NAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    const DAY_SHORT = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    /** Column order of the timetable: Monday first, Sunday last. */
    const WEEK_ORDER = [1, 2, 3, 4, 5, 6, 0];
    /** Day names, full or abbreviated ("Thu", "Thurs", "Thursday"), as 0 (Sunday) to 6. */
    const DAY_WORDS = [
        [0, /^su(n(day)?)?$/], [1, /^m(on(day)?)?$/], [2, /^tu(e(s(day)?)?)?$/], [3, /^w(ed(nesday)?)?$/],
        [4, /^th(u(r(s(day)?)?)?)?$/], [5, /^f(ri(day)?)?$/], [6, /^sa(t(urday)?)?$/]
    ];
    /** Letters of registrar shorthand such as "MWF" or "TTh". */
    const DAY_LETTERS = { m: 1, t: 2, tu: 2, w: 3, th: 4, f: 5, s: 6, sa: 6, su: 0 };
    /** Subject colours defined in student-style.css (.tone-1 to .tone-8). */
    const TONE_COUNT = 8;
    /** Fee colours defined in student-style.css (.fee-1 to .fee-6). */
    const FEE_TONE_COUNT = 6;

    /** The week's class meetings, parsed from the schedule rows; the agendas' day buttons redraw from it. */
    let scheduleMeetings = [];
    let toneCache = { data: null, tones: new Map() };

    /**
     * Markup for one icon from the page's sprite (the <svg class="sprite">
     * at the top of student_dashboard.html).
     *
     * @param {string} name - Symbol name without its "i-" prefix.
     * @returns {string} SVG markup.
     */
    function icon(name) {
        return `<svg class="ic" aria-hidden="true" focusable="false"><use href="#i-${name}"></use></svg>`;
    }

    /**
     * @param {string} message - Text shown when a list has nothing to show.
     * @returns {string} An empty-state paragraph.
     */
    function emptyHtml(message) {
        return `<p class="empty">${escapeHtml(message)}</p>`;
    }

    /**
     * Title-cases text: "KHYNNE MARK" becomes "Khynne Mark", "DELEÑA"
     * becomes "Deleña".
     *
     * @param {string} text - Text to convert.
     * @returns {string} Title-cased text.
     */
    function titleCase(text) {
        return String(text || '').toLowerCase().replace(/(^|[\s\-'’])(\p{L})/gu, (match, lead, letter) => lead + letter.toUpperCase());
    }

    /**
     * Display forms of the registrar's "SURNAME, GIVEN NAMES" (e.g. "LAWAN,
     * KHYNNE MARK ELMER"). An all-caps part is title-cased for display; a
     * name already in mixed case is kept exactly as stored. The Profile
     * table and the printed report still show the record verbatim.
     *
     * @param {string} fullName - Student.fullName.
     * @returns {{full: string, short: string, first: string, initials: string}}
     */
    function nameParts(fullName) {
        const raw = String(fullName || '').trim();
        const comma = raw.indexOf(',');
        const tidy = part => (part && part === part.toUpperCase() && part !== part.toLowerCase()) ? titleCase(part) : part;
        const family = tidy(comma >= 0 ? raw.slice(0, comma).trim() : '');
        const given = tidy(comma >= 0 ? raw.slice(comma + 1).trim() : raw);
        const givenWords = given.split(/\s+/).filter(Boolean);
        const first = (givenWords[0] || '').replace(/[,.]+$/, '');
        return {
            full: [given, family].filter(Boolean).join(' ') || 'Student',
            short: [first, family].filter(Boolean).join(' ') || 'Student',
            first: first || family || 'Student',
            initials: (first.charAt(0) + (family || givenWords[1] || '').charAt(0)).toUpperCase() || 'S'
        };
    }

    /**
     * @param {Date} date - The device's current time.
     * @returns {string} "Good morning", "Good afternoon" or "Good evening".
     */
    function greetingFor(date) {
        const hour = date.getHours();
        if (hour < 12) return 'Good morning';
        return hour < 18 ? 'Good afternoon' : 'Good evening';
    }

    /**
     * Shortens "1st Semester, 2025-2026" to "1st Sem · 2025–26" for the term
     * chip. Any other wording is returned unchanged.
     *
     * @param {string} term - The API's currentTerm.
     * @returns {string} Short label.
     */
    function shortTerm(term) {
        const text = String(term || '').trim();
        const match = /^(\d)(st|nd|rd|th)\s+sem(ester)?,?\s*(\d{4})\s*[-–]\s*(\d{4})$/i.exec(text);
        return match ? `${match[1]}${match[2]} Sem · ${match[4]}–${match[5].slice(2)}` : text;
    }

    /**
     * @param {string} text - A date as the API sends it, e.g. "2026-03-01".
     * @returns {string} "Mar 1, 2026" for an ISO date, else the text unchanged.
     */
    function formatDate(text) {
        if (!/^\d{4}-\d{2}-\d{2}$/.test(String(text || ''))) return String(text || '');
        return new Date(`${text}T00:00:00`).toLocaleDateString('en-PH', { year: 'numeric', month: 'short', day: 'numeric' });
    }

    /**
     * @param {number|null} value - A grade or GWA.
     * @returns {string} Two decimals, or an em dash when there is none.
     */
    function formatGrade(value) {
        return Number.isFinite(value) ? value.toFixed(2) : '—';
    }

    /**
     * Where a grade sits on the bar, as a percentage. The bar runs from 5.00
     * on the left to 1.00 on the right, so a better grade fills more of it:
     * the Philippine scale counts down, with 1.00 the highest grade.
     *
     *     (5.00 - 1.25) / 4 = 93.75% for a GWA of 1.25
     *
     * @param {number|null} value - A grade or GWA.
     * @returns {number} 0 to 100.
     */
    function scalePercent(value) {
        return Number.isFinite(value) ? Math.min(100, Math.max(0, ((5 - value) / 4) * 100)) : 0;
    }

    /**
     * @param {string} barId - id of a .scale__fill element.
     * @param {number|null} value - The grade it shows.
     * @returns {void}
     */
    function setScale(barId, value) {
        document.getElementById(barId).style.width = `${scalePercent(value)}%`;
    }

    /**
     * Same rule as public/admin_dashboard.js's grade report, so a "Failed"
     * remark reads as a failure here too instead of a green badge.
     *
     * @param {string|null} remarks - e.g. "Passed" or "Failed".
     * @returns {string} "ok", "bad" or "neutral".
     */
    function remarkTone(remarks) {
        if (/fail/i.test(remarks || '')) return 'bad';
        if (/pass/i.test(remarks || '')) return 'ok';
        return 'neutral';
    }

    /**
     * A grade's colour: its remark when that says passed or failed, otherwise
     * the grade itself (3.00 or better passes, 4.00 is conditional, 5.00
     * fails). No grade yet (INC, dropped) stays neutral.
     *
     * @param {object} grade - A row of the API's `grades`.
     * @returns {string} "ok", "warn", "bad" or "neutral".
     */
    function gradeTone(grade) {
        if (!Number.isFinite(grade.grade)) return 'neutral';
        const byRemark = remarkTone(grade.remarks);
        if (byRemark !== 'neutral') return byRemark;
        if (grade.grade <= 3) return 'ok';
        return grade.grade < 5 ? 'warn' : 'bad';
    }

    /**
     * @param {object} grade - A row of the API's `grades`.
     * @returns {string} "1.25 · Passed", or the remark alone ("INC") when there is no grade yet.
     */
    function gradeLabel(grade) {
        if (!Number.isFinite(grade.grade)) return grade.remarks || 'In progress';
        return grade.remarks ? `${grade.grade.toFixed(2)} · ${grade.remarks}` : grade.grade.toFixed(2);
    }

    /**
     * @param {string} standing - stats.academicStanding.
     * @returns {string} "ok", "bad" or "neutral".
     */
    function standingTone(standing) {
        if (/good/i.test(standing || '')) return 'ok';
        if (/probation/i.test(standing || '')) return 'bad';
        return 'neutral';
    }

    /**
     * @param {string} status - Student.status: ENROLLED, IRREGULAR or DROPPED.
     * @returns {string} "ok", "warn" or "bad".
     */
    function statusTone(status) {
        if (status === 'ENROLLED') return 'ok';
        return status === 'DROPPED' ? 'bad' : 'warn';
    }

    /**
     * @param {string} status - A clearance row's status, e.g. "Cleared".
     * @returns {string} "ok", "warn" or "neutral".
     */
    function clearanceTone(status) {
        if (/^cleared$/i.test(status || '')) return 'ok';
        return /pending|hold|deficien/i.test(status || '') ? 'warn' : 'neutral';
    }

    /**
     * @param {object} data - Parsed response body.
     * @returns {Array<object>} The current term's grade rows: the subjects the student is taking now.
     */
    function currentCourses(data) {
        return data.grades.filter(grade => grade.term === data.currentTerm);
    }

    /**
     * The colour (1 to TONE_COUNT) a subject wears on every screen: this
     * term's subjects first, then any others, each group in subject-code
     * order. Sorting matters because the API lists grades by last update, so
     * colours taken in that order would all shift whenever an admin edited
     * one grade.
     *
     * @param {object} data - Parsed response body.
     * @param {string} subjectCode - e.g. "SE301".
     * @returns {number} Tone number for a .tone-N class.
     */
    function toneFor(data, subjectCode) {
        if (toneCache.data !== data) {
            const tones = new Map();
            const byCode = rows => rows.map(row => row.subjectCode).sort((a, b) => String(a).localeCompare(String(b)));
            [...byCode(currentCourses(data)), ...byCode(data.grades), ...byCode(data.schedule)].forEach(code => {
                if (!tones.has(code)) tones.set(code, (tones.size % TONE_COUNT) + 1);
            });
            toneCache = { data, tones };
        }
        return toneCache.tones.get(subjectCode) || TONE_COUNT;
    }

    /**
     * @param {string} code - A subject code.
     * @returns {string} Its leading letters, e.g. "IAS" for IAS301.
     */
    function subjectInitials(code) {
        const letters = String(code || '').match(/^[A-Za-z]+/);
        return (letters ? letters[0] : String(code || '?')).slice(0, 4).toUpperCase();
    }

    /**
     * Reads a timetable string such as "Mon / Wed · 08:00 AM - 09:30 AM",
     * "Friday · 03:30 PM - 06:30 PM", or registrar shorthand like
     * "MWF 8:00-9:00 AM".
     *
     * @param {string} text - A schedule row's `schedule` field.
     * @returns {{days: number[], start: number, end: number}|null} Days as 0
     * (Sunday) to 6 and times as minutes after midnight; null if unreadable.
     */
    function parseSchedule(text) {
        const value = String(text || '');
        const time = /(\d{1,2}):(\d{2})\s*([ap])?\.?\s*m?\.?\s*(?:-|–|—|to)\s*(\d{1,2}):(\d{2})\s*([ap])?\.?\s*m?\.?/i.exec(value);
        if (!time) return null;

        const toMinutes = (hours, minutes, meridiem) => {
            let hour = Number(hours);
            if (meridiem) hour = (hour % 12) + (meridiem.toLowerCase() === 'p' ? 12 : 0);
            return hour * 60 + Number(minutes);
        };
        const end = toMinutes(time[4], time[5], time[6]);
        // "8:00 - 9:30 AM": a start without its own AM/PM takes the end's,
        // unless that would put it after the end ("11:00 - 1:00 PM").
        let start = toMinutes(time[1], time[2], time[3] || time[6]);
        if (!time[3] && time[6] && start >= end) start = toMinutes(time[1], time[2], 'a');

        const days = [];
        const addDay = day => { if (!days.includes(day)) days.push(day); };
        value.slice(0, time.index).toLowerCase().split(/[^a-z]+/).filter(Boolean).forEach(word => {
            const named = DAY_WORDS.find(([, pattern]) => pattern.test(word));
            if (named) {
                addDay(named[0]);
                return;
            }
            const letters = word.match(/th|tu|sa|su|[mtwfs]/g);
            if (letters && letters.join('') === word) letters.forEach(letter => addDay(DAY_LETTERS[letter]));
        });

        return days.length && end > start ? { days, start, end } : null;
    }

    /**
     * Every class meeting of the week, Monday to Sunday and then by time. A
     * row whose schedule can't be read is left off the timetable but is
     * still listed, verbatim, in the Schedule section's table.
     *
     * @param {object} data - Parsed response body.
     * @returns {Array<{row: object, day: number, start: number, end: number, tone: number}>}
     */
    function buildMeetings(data) {
        const meetings = [];
        data.schedule.forEach(row => {
            const parsed = parseSchedule(row.schedule);
            if (!parsed) return;
            parsed.days.forEach(day => meetings.push({ row, day, start: parsed.start, end: parsed.end, tone: toneFor(data, row.subjectCode) }));
        });
        return meetings.sort((a, b) => (WEEK_ORDER.indexOf(a.day) - WEEK_ORDER.indexOf(b.day)) || (a.start - b.start));
    }

    /**
     * @param {number} minutes - Minutes after midnight.
     * @param {boolean} [withMeridiem=true] - Append AM/PM.
     * @returns {string} e.g. "8:00 AM", or "8:00".
     */
    function formatClock(minutes, withMeridiem = true) {
        const hour24 = Math.floor(minutes / 60) % 24;
        const clock = `${hour24 % 12 || 12}:${String(minutes % 60).padStart(2, '0')}`;
        return withMeridiem ? `${clock} ${hour24 < 12 ? 'AM' : 'PM'}` : clock;
    }

    /**
     * @param {number} start - Minutes after midnight.
     * @param {number} end - Minutes after midnight.
     * @returns {string} "8:00–9:30 AM", or "11:00 AM–1:00 PM" across noon.
     */
    function formatRange(start, end) {
        const sameHalf = (start < 720) === (end < 720);
        return `${formatClock(start, !sameHalf)}–${formatClock(end)}`;
    }

    /**
     * @param {number[]} days - 0 (Sunday) to 6.
     * @returns {string} "Mon & Wed", "Mon, Wed & Fri".
     */
    function formatDays(days) {
        const names = WEEK_ORDER.filter(day => days.includes(day)).map(day => DAY_SHORT[day]);
        return names.length > 1 ? `${names.slice(0, -1).join(', ')} & ${names[names.length - 1]}` : (names[0] || '');
    }

    /**
     * The meeting in progress, or else the next one to start, wrapping into
     * next week.
     *
     * @param {Array<object>} meetings - From buildMeetings().
     * @param {Date} now - The device's current time.
     * @returns {{meeting: object, daysAhead: number, ongoing: boolean}|null}
     */
    function nextMeeting(meetings, now) {
        const today = now.getDay();
        const minute = now.getHours() * 60 + now.getMinutes();
        let best = null;
        meetings.forEach(meeting => {
            let daysAhead = (meeting.day - today + 7) % 7;
            const ongoing = daysAhead === 0 && meeting.start <= minute && minute < meeting.end;
            if (daysAhead === 0 && meeting.end <= minute) daysAhead = 7;
            const rank = ongoing ? -1 : daysAhead * 1440 + meeting.start;
            if (!best || rank < best.rank) best = { meeting, daysAhead, ongoing, rank };
        });
        return best;
    }

    /**
     * Inside of Home's "Next class" card.
     *
     * @param {object} data - Parsed response body.
     * @param {Date} now - The device's current time.
     * @returns {string} Card markup.
     */
    function nextClassHtml(data, now) {
        const header = '<div class="next__top"><span class="next__eyebrow">Next class</span><span class="chip chip--on-brand">Sample schedule</span></div>';
        const next = nextMeeting(scheduleMeetings, now);

        if (!next) {
            const row = data.schedule[0];
            return header + (row
                ? `<p class="next__when">${escapeHtml(row.schedule)}</p><p class="next__what">${escapeHtml(row.subjectCode)} · ${escapeHtml(row.subjectTitle)}</p>`
                : '<p class="next__when">No classes on file</p>');
        }

        const { meeting, daysAhead, ongoing } = next;
        let when;
        if (ongoing) {
            when = `Now · until ${formatClock(meeting.end)}`;
        } else {
            const day = daysAhead === 0 ? 'Today'
                : daysAhead === 1 ? 'Tomorrow'
                : daysAhead === 7 ? `Next ${DAY_NAMES[meeting.day]}`
                : DAY_NAMES[meeting.day];
            when = `${day} · ${formatClock(meeting.start)}`;
        }

        return `${header}
            <p class="next__when">${escapeHtml(when)}</p>
            <p class="next__what">${escapeHtml(meeting.row.subjectCode)} · ${escapeHtml(meeting.row.subjectTitle)}</p>
            <ul class="next__meta">
                <li>${icon('clock')}${escapeHtml(formatRange(meeting.start, meeting.end))}</li>
                <li>${icon('pin')}${escapeHtml(meeting.row.room)}</li>
                <li>${icon('user')}${escapeHtml(meeting.row.instructor)}</li>
            </ul>`;
    }

    /**
     * One course card: the subject from the student's grade row, plus the
     * sample timetable row with the same subject code, when there is one.
     *
     * @param {object} data - Parsed response body.
     * @param {object} course - A row of the API's `grades`.
     * @param {Map<string, object>} scheduleByCode - Schedule rows by subject code.
     * @returns {string} Card markup.
     */
    function courseCardHtml(data, course, scheduleByCode) {
        const row = scheduleByCode.get(course.subjectCode);
        const parsed = row ? parseSchedule(row.schedule) : null;
        const when = parsed ? `${formatDays(parsed.days)} · ${formatRange(parsed.start, parsed.end)}` : (row ? row.schedule : '');
        const units = `${course.units} unit${Number(course.units) === 1 ? '' : 's'}`;
        const facts = row
            ? `<li>${icon('clock')}<span>${escapeHtml(when)}</span></li><li>${icon('pin')}<span>${escapeHtml(row.room)}</span></li>`
            : `<li class="course__facts-empty">${icon('clock')}<span>No schedule posted yet</span></li>`;

        return `
            <article class="course tone-${toneFor(data, course.subjectCode)}">
                <div class="course__top">
                    <span class="course__tile" aria-hidden="true">${escapeHtml(subjectInitials(course.subjectCode))}</span>
                    <span class="pill pill--${gradeTone(course)}">${escapeHtml(gradeLabel(course))}</span>
                </div>
                <div>
                    <p class="course__code">${escapeHtml(course.subjectCode)}</p>
                    <h3 class="course__title">${escapeHtml(course.subjectTitle)}</h3>
                    <p class="course__meta">${escapeHtml(units)}${row ? ` · ${escapeHtml(row.instructor)}` : ''}</p>
                </div>
                <ul class="course__facts">${facts}</ul>
            </article>`;
    }

    /**
     * One row of Home's "Recent grades" list.
     *
     * @param {object} data - Parsed response body.
     * @param {object} grade - A row of the API's `grades`.
     * @returns {string} List item markup.
     */
    function gradeRowHtml(data, grade) {
        const hasGrade = Number.isFinite(grade.grade);
        const remark = hasGrade && grade.remarks ? `<span class="sr-only">, ${escapeHtml(grade.remarks)}</span>` : '';
        return `
            <li class="grade-row tone-${toneFor(data, grade.subjectCode)}">
                <span class="grade-row__tile" aria-hidden="true">${escapeHtml(subjectInitials(grade.subjectCode))}</span>
                <span class="grade-row__text"><strong>${escapeHtml(grade.subjectCode)}</strong><span>${escapeHtml(grade.subjectTitle)}</span></span>
                <span class="grade-chip grade-chip--${gradeTone(grade)}">${escapeHtml(hasGrade ? grade.grade.toFixed(2) : (grade.remarks || '—'))}${remark}</span>
            </li>`;
    }

    /**
     * Desktop timetable: one column per weekday (Saturday and Sunday only
     * when a class falls on them), from 7:00 AM to 7:00 PM unless a class
     * runs earlier or later. A block's top and height are its start time
     * and its length as percentages of that window; a short block drops
     * the room line, or the time too, rather than cut them in half.
     *
     * @param {Array<object>} meetings - From buildMeetings().
     * @param {number} today - 0 (Sunday) to 6, highlighted.
     * @returns {string} Timetable markup.
     */
    function weekHtml(meetings, today) {
        if (!meetings.length) return emptyHtml('No classes on the timetable.');

        const days = WEEK_ORDER.filter(day => (day >= 1 && day <= 5) || meetings.some(m => m.day === day));
        const firstHour = Math.min(7, ...meetings.map(m => Math.floor(m.start / 60)));
        const lastHour = Math.max(19, ...meetings.map(m => Math.ceil(m.end / 60)));
        const span = (lastHour - firstHour) * 60;
        const percent = minutes => `${((minutes / span) * 100).toFixed(3)}%`;

        const labels = [];
        for (let hour = firstHour + 1; hour < lastHour; hour += 2) {
            labels.push(`<span style="top:${percent((hour - firstHour) * 60)}">${formatClock(hour * 60).replace(':00', '')}</span>`);
        }

        const columns = days.map(day => {
            const blocks = meetings.filter(m => m.day === day).map(m => {
                const length = m.end - m.start;
                const size = length < 75 ? ' week__block--tiny' : length < 120 ? ' week__block--compact' : '';
                return `
                <div class="week__block tone-${m.tone}${size}" style="top:${percent(m.start - firstHour * 60)};height:${percent(length)}">
                    <span class="week__code">${escapeHtml(m.row.subjectCode)}</span>
                    <span class="week__time">${escapeHtml(formatRange(m.start, m.end))}</span>
                    <span class="week__room">${escapeHtml(m.row.room)}</span>
                </div>`;
            }).join('');
            return `
                <div class="week__day${day === today ? ' is-today' : ''}" role="group" aria-label="${DAY_NAMES[day]}">
                    <div class="week__head">${DAY_SHORT[day]}</div>
                    <div class="week__col">${blocks}</div>
                </div>`;
        }).join('');

        return `
            <div class="week" style="--hours:${lastHour - firstHour}">
                <div class="week__axis" aria-hidden="true">${labels.join('')}</div>
                <div class="week__days" style="grid-template-columns:repeat(${days.length}, minmax(0, 1fr))">${columns}</div>
            </div>`;
    }

    /**
     * Phone timetable: a row of day buttons and the chosen day's classes.
     *
     * @param {Array<object>} meetings - From buildMeetings().
     * @param {number} selectedDay - 0 (Sunday) to 6.
     * @param {number} today - 0 (Sunday) to 6, outlined.
     * @returns {string} Agenda markup.
     */
    function agendaHtml(meetings, selectedDay, today) {
        const days = WEEK_ORDER.filter(day => (day >= 1 && day <= 5) || meetings.some(m => m.day === day));
        const buttons = days.map(day => {
            const hasClass = meetings.some(m => m.day === day);
            const classes = ['day-chip'];
            if (day === selectedDay) classes.push('is-selected');
            if (day === today) classes.push('is-today');
            return `
                <button type="button" class="${classes.join(' ')}" data-day="${day}" aria-pressed="${day === selectedDay}" aria-label="${DAY_NAMES[day]}${hasClass ? '' : ', no classes'}">
                    <span>${DAY_SHORT[day]}</span>${hasClass ? '<span class="day-chip__dot" aria-hidden="true"></span>' : ''}
                </button>`;
        }).join('');

        const items = meetings.filter(m => m.day === selectedDay);
        const list = items.length
            ? `<ol class="agenda__list">${items.map(m => `
                <li class="agenda__item">
                    <p class="agenda__time"><span>${formatClock(m.start)}</span><span>${formatClock(m.end)}</span></p>
                    <div class="agenda__card tone-${m.tone}">
                        <p class="agenda__what"><strong>${escapeHtml(m.row.subjectCode)}</strong> · ${escapeHtml(m.row.subjectTitle)}</p>
                        <p class="agenda__where">${escapeHtml(m.row.room)} · ${escapeHtml(m.row.instructor)}</p>
                    </div>
                </li>`).join('')}</ol>`
            : `<p class="agenda__empty">No classes on ${DAY_NAMES[selectedDay]}.</p>`;

        return `<div class="day-picker" role="group" aria-label="Day of the week">${buttons}</div>${list}`;
    }

    /**
     * @param {Array<object>} meetings - From buildMeetings().
     * @param {Date} now - The device's current time.
     * @returns {number} Today when it has classes, else the next class's day (Monday if none).
     */
    function defaultAgendaDay(meetings, now) {
        if (meetings.some(m => m.day === now.getDay())) return now.getDay();
        const next = nextMeeting(meetings, now);
        return next ? next.meeting.day : 1;
    }

    /**
     * Draws (or redraws) one agenda. The chosen day lives on the element
     * itself, so Home's agenda and the Schedule section's keep their own.
     *
     * @param {HTMLElement} container - An element with a data-agenda attribute.
     * @param {number} day - 0 (Sunday) to 6.
     * @returns {void}
     */
    function renderAgenda(container, day) {
        container.dataset.day = String(day);
        container.innerHTML = scheduleMeetings.length
            ? agendaHtml(scheduleMeetings, day, new Date().getDay())
            : emptyHtml('No classes on the timetable.');
    }

    // Day buttons are redrawn on every pick, so one listener on the
    // document serves all of them; focus returns to the day just picked.
    document.addEventListener('click', (event) => {
        const dayButton = event.target.closest('[data-day]');
        const agenda = dayButton && dayButton.closest('[data-agenda]');
        if (!agenda) return;
        const day = Number(dayButton.dataset.day);
        renderAgenda(agenda, day);
        const picked = agenda.querySelector(`[data-day="${day}"]`);
        if (picked) picked.focus();
    });

    /**
     * @param {Array<object>} fees - billing.fees.
     * @returns {string} Bar segments, each as wide as its share of the total.
     */
    function feeBarHtml(fees) {
        const total = fees.reduce((sum, fee) => sum + (Number(fee.amount) || 0), 0);
        if (!total) return '';
        return fees.map((fee, index) => {
            const share = ((Number(fee.amount) || 0) / total) * 100;
            return `<span class="stack-bar__seg fee-${(index % FEE_TONE_COUNT) + 1}" style="width:${share.toFixed(3)}%"></span>`;
        }).join('');
    }

    /**
     * @param {Array<object>} fees - billing.fees.
     * @returns {string} Legend rows for the fee bar, with the total.
     */
    function feeLegendHtml(fees) {
        const total = fees.reduce((sum, fee) => sum + (Number(fee.amount) || 0), 0);
        return fees.map((fee, index) => `
            <li><span class="legend-dot fee-${(index % FEE_TONE_COUNT) + 1}" aria-hidden="true"></span><span class="legend__label">${escapeHtml(fee.type)}</span><span class="legend__value">${formatCurrency(fee.amount)}</span></li>`).join('')
            + `<li class="legend__total"><span class="legend__label">Total assessment</span><span class="legend__value">${formatCurrency(total)}</span></li>`;
    }

    /**
     * @param {Array<object>} rows - The API's `clearance`.
     * @returns {string} One bar segment per requirement, coloured by status.
     */
    function clearanceBarHtml(rows) {
        return rows.map(row => `<span class="seg-bar__seg seg-bar__seg--${clearanceTone(row.status)}"></span>`).join('');
    }

    /**
     * Fills everything that shows who is signed in - the sidebar's user
     * card, the avatars, the term chip, Home's greeting and the Profile
     * section - from a GET /api/students/me response.
     *
     * @param {object} data - Parsed response body.
     * @returns {void}
     */
    function renderProfile(data) {
        const { profile, stats } = data;
        const name = nameParts(profile.fullName);

        homeTitle = `${greetingFor(new Date())}, ${name.first}`;
        if (!document.getElementById('section-home').hidden) {
            document.getElementById('main-title').textContent = homeTitle;
        }

        ['sidebarAvatar', 'headAvatar', 'homeAvatar', 'profileAvatar'].forEach(id => {
            document.getElementById(id).textContent = name.initials;
        });
        document.getElementById('headAvatar').setAttribute('aria-label', `Open your profile (${name.full})`);
        document.getElementById('sidebarUserName').textContent = name.short;
        document.getElementById('sidebarUserId').textContent = profile.studentId;
        document.getElementById('termChipText').textContent = shortTerm(data.currentTerm);
        document.getElementById('termChip').title = data.currentTerm || '';

        document.getElementById('profileFullName').textContent = name.full;
        document.getElementById('profileSummary').textContent =
            `Student ID: ${profile.studentId} · ${profile.program} · ${profile.yearLevel}`;

        const badge = document.getElementById('profileStatusBadge');
        badge.textContent = titleCase(profile.status);
        badge.className = `pill pill--${statusTone(profile.status)}`;

        const standing = document.getElementById('profileStanding');
        standing.textContent = stats.academicStanding;
        standing.className = `pill pill--${standingTone(stats.academicStanding)}`;

        const rows = [
            ['Full Name', profile.fullName],
            ['Student ID', profile.studentId],
            ['Program', profile.program],
            ['Year Level', profile.yearLevel],
            ['Department', profile.department],
            ['Email Address', profile.email],
            ['Enrollment Status', titleCase(profile.status)]
        ];
        document.getElementById('profileInfoTableBody').innerHTML = rows
            .map(([label, value]) => `<tr><th scope="row">${escapeHtml(label)}</th><td>${escapeHtml(value || '—')}</td></tr>`)
            .join('');
    }

    /**
     * Fills the Home section: the profile summary, next class, KPI tiles,
     * course cards, this week's timetable, recent grades, and the Account
     * and Clearance cards.
     *
     * @param {object} data - Parsed response body.
     * @returns {void}
     */
    function renderHome(data) {
        const { profile, stats, grades, billing, clearance } = data;
        const name = nameParts(profile.fullName);
        const now = new Date();
        const courses = currentCourses(data);
        const scheduleByCode = new Map(data.schedule.map(row => [row.subjectCode, row]));
        scheduleMeetings = buildMeetings(data);

        document.getElementById('homeName').textContent = name.full;
        document.getElementById('homeMeta').textContent = `${profile.studentId} · ${profile.program} · ${profile.yearLevel}`;
        document.getElementById('homeChips').innerHTML = [
            `<span class="pill pill--${statusTone(profile.status)}">${escapeHtml(titleCase(profile.status))}</span>`,
            `<span class="pill pill--${standingTone(stats.academicStanding)}">${escapeHtml(stats.academicStanding)}</span>`,
            profile.department ? `<span class="pill pill--neutral">${escapeHtml(profile.department)}</span>` : ''
        ].join('');

        document.getElementById('nextClass').innerHTML = nextClassHtml(data, now);

        document.getElementById('statGwa').textContent = formatGrade(stats.gwa);
        setScale('statGwaBar', stats.gwa);
        document.getElementById('statEnrolledUnits').textContent = stats.enrolledUnits;
        document.getElementById('statSubjects').textContent = `${grades.length} subject${grades.length === 1 ? '' : 's'} on record`;
        const standing = document.getElementById('statStanding');
        standing.textContent = stats.academicStanding;
        standing.className = `kpi__value kpi__value--text tone-text--${standingTone(stats.academicStanding)}`;
        document.getElementById('statBalance').textContent = formatCurrency(billing.balanceDue);
        document.getElementById('statBalanceNote').textContent = billing.status;

        document.getElementById('homeCoursesCount').textContent = courses.length ? `(${courses.length})` : '';
        document.getElementById('homeCourses').innerHTML = courses.length
            ? courses.slice(0, 6).map(course => courseCardHtml(data, course, scheduleByCode)).join('')
            : emptyHtml('No subjects on file for this term.');

        document.getElementById('homeWeek').innerHTML = weekHtml(scheduleMeetings, now.getDay());
        renderAgenda(document.getElementById('homeAgenda'), defaultAgendaDay(scheduleMeetings, now));

        document.getElementById('homeGwa').textContent = formatGrade(stats.gwa);
        setScale('homeGwaBar', stats.gwa);
        const homeStanding = document.getElementById('homeStanding');
        homeStanding.textContent = stats.academicStanding;
        homeStanding.className = `gwa-box__standing tone-text--${standingTone(stats.academicStanding)}`;
        const recent = grades.filter(grade => Number.isFinite(grade.grade) || grade.remarks);
        document.getElementById('homeGradesList').innerHTML = recent.length
            ? recent.slice(0, 5).map(grade => gradeRowHtml(data, grade)).join('')
            : `<li>${emptyHtml('No grades on file yet.')}</li>`;

        document.getElementById('homeBalance').textContent = formatCurrency(billing.balanceDue);
        const balanceStatus = document.getElementById('homeBalanceStatus');
        balanceStatus.textContent = billing.status;
        balanceStatus.className = `status-text status-text--${Number(billing.balanceDue) > 0 ? 'warn' : 'ok'}`;
        document.getElementById('homeFeeBar').innerHTML = feeBarHtml(billing.fees);
        document.getElementById('homeFeeLegend').innerHTML = feeLegendHtml(billing.fees);

        const cleared = clearance.filter(row => clearanceTone(row.status) === 'ok').length;
        const allCleared = clearance.length > 0 && cleared === clearance.length;
        document.getElementById('statClearance').textContent = clearance.length ? `${cleared} of ${clearance.length}` : '—';
        const clearanceNote = document.getElementById('homeClearanceNote');
        clearanceNote.textContent = !clearance.length ? 'No clearance records on file'
            : allCleared ? 'All offices cleared'
            : `${clearance.length - cleared} still pending`;
        clearanceNote.className = clearance.length ? `status-text status-text--${allCleared ? 'ok' : 'warn'}` : 'status-text';
        document.getElementById('homeClearanceBar').innerHTML = clearanceBarHtml(clearance);
        document.getElementById('homeClearanceList').innerHTML = clearance.map(row => {
            const tone = clearanceTone(row.status);
            const office = String(row.requirement || '').replace(/\s+clearance$/i, '');
            return `<li class="pill pill--${tone}">${tone === 'ok' ? icon('check') : ''}${escapeHtml(office)}</li>`;
        }).join('');
    }

    /**
     * Fills the My Courses section: one card per subject of the current term.
     *
     * @param {object} data - Parsed response body.
     * @returns {void}
     */
    function renderCourses(data) {
        const courses = currentCourses(data);
        const scheduleByCode = new Map(data.schedule.map(row => [row.subjectCode, row]));
        const units = courses.reduce((sum, course) => sum + (Number(course.units) || 0), 0);

        document.getElementById('coursesHeading').textContent = data.currentTerm || 'This term';
        document.getElementById('coursesSummary').textContent = courses.length
            ? `${courses.length} subject${courses.length === 1 ? '' : 's'} · ${units} unit${units === 1 ? '' : 's'}`
            : '';
        document.getElementById('coursesGrid').innerHTML = courses.length
            ? courses.map(course => courseCardHtml(data, course, scheduleByCode)).join('')
            : emptyHtml('No subjects on file for this term.');
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
        const now = new Date();
        scheduleMeetings = buildMeetings(data);

        document.getElementById('scheduleTitle').textContent = `Weekly timetable · ${data.currentTerm}`;
        document.getElementById('scheduleWeek').innerHTML = weekHtml(scheduleMeetings, now.getDay());
        renderAgenda(document.getElementById('scheduleAgenda'), defaultAgendaDay(scheduleMeetings, now));

        const body = document.getElementById('scheduleTableBody');
        if (!data.schedule.length) {
            body.innerHTML = '<tr><td colspan="6">No schedule on file.</td></tr>';
            return;
        }

        body.innerHTML = data.schedule.map(row => {
            const parsed = parseSchedule(row.schedule);
            const when = parsed ? `${formatDays(parsed.days)} · ${formatRange(parsed.start, parsed.end)}` : row.schedule;
            return `
            <tr>
                <td data-label=""><span class="code-cell tone-${toneFor(data, row.subjectCode)}"><span class="code-cell__dot" aria-hidden="true"></span>${escapeHtml(row.subjectCode)}</span></td>
                <td data-label="">${escapeHtml(row.subjectTitle)}</td>
                <td class="num" data-label="Units">${escapeHtml(row.units)}</td>
                <td class="nowrap" data-label="Day / Time">${escapeHtml(when)}</td>
                <td class="nowrap" data-label="Room">${escapeHtml(row.room)}</td>
                <td class="nowrap" data-label="Instructor">${escapeHtml(row.instructor)}</td>
            </tr>`;
        }).join('');
    }

    /**
     * Populates the Grades section from real Grade/Subject rows: the summary
     * tiles, the term filter, the table, and the printed report's letterhead.
     *
     * @param {object} data - Parsed response body.
     * @returns {void}
     */
    function renderGrades(data) {
        const { grades, stats, profile } = data;
        const graded = grades.filter(grade => Number.isFinite(grade.grade));
        const gradedUnits = graded.reduce((sum, grade) => sum + (Number(grade.units) || 0), 0);

        document.getElementById('gradesGwa').textContent = formatGrade(stats.gwa);
        setScale('gradesGwaBar', stats.gwa);
        const standing = document.getElementById('gradesStanding');
        standing.textContent = stats.academicStanding;
        standing.className = `kpi__value kpi__value--text tone-text--${standingTone(stats.academicStanding)}`;
        document.getElementById('gradesGraded').textContent = `${graded.length} of ${grades.length}`;
        document.getElementById('gradesGradedNote').textContent = `${gradedUnits} graded unit${gradedUnits === 1 ? '' : 's'}`;

        document.getElementById('printName').textContent = profile.fullName;
        document.getElementById('printStudentId').textContent = profile.studentId;
        document.getElementById('printProgram').textContent = `${profile.program} · ${profile.yearLevel}`;
        document.getElementById('printFoot').textContent =
            `General Weighted Average: ${formatGrade(stats.gwa)} (${stats.academicStanding}), across all graded subjects on record.`;

        // One option per term on record, with "All terms" first when there is
        // more than one (or when some rows have no term). Built with
        // new Option() rather than markup, so a term's text can never be read
        // as HTML.
        const ALL_TERMS = '__all__';
        const terms = [...new Set(grades.map(grade => grade.term).filter(Boolean))];
        const needsAll = terms.length > 1 || grades.some(grade => !grade.term);
        const termFilter = document.getElementById('gradesTermFilter');
        termFilter.replaceChildren(...(terms.length
            ? [...(needsAll ? [new Option('All terms', ALL_TERMS)] : []), ...terms.map(term => new Option(term, term))]
            : [new Option('No Term on File', ALL_TERMS)]));

        const drawRows = () => {
            const picked = termFilter.value;
            const rows = picked === ALL_TERMS ? grades : grades.filter(grade => grade.term === picked);
            document.getElementById('printTerm').textContent = picked === ALL_TERMS ? (terms.length ? 'All terms' : '—') : picked;

            const body = document.getElementById('gradesTableBody');
            if (!rows.length) {
                body.innerHTML = '<tr><td colspan="5">No grades on file yet.</td></tr>';
                return;
            }

            body.innerHTML = rows.map(grade => `
                <tr>
                    <td data-label=""><span class="code-cell tone-${toneFor(data, grade.subjectCode)}"><span class="code-cell__dot" aria-hidden="true"></span>${escapeHtml(grade.subjectCode)}</span></td>
                    <td data-label="">${escapeHtml(grade.subjectTitle)}</td>
                    <td class="num" data-label="Units">${escapeHtml(grade.units)}</td>
                    <td class="num grade-cell" data-label="Grade">${escapeHtml(formatGrade(grade.grade))}</td>
                    <td data-label="Remarks"><span class="pill pill--${gradeTone(grade)}">${escapeHtml(grade.remarks || '—')}</span></td>
                </tr>
            `).join('');
        };

        termFilter.onchange = drawRows;
        drawRows();
    }

    // The printed report's time stamp is taken when the print dialog opens.
    window.addEventListener('beforeprint', () => {
        document.getElementById('printStamp').textContent =
            `Printed ${new Date().toLocaleString('en-PH', { dateStyle: 'medium', timeStyle: 'short' })}`;
    });

    /**
     * Populates the Account/Billing Assessment section. Like Schedule, this
     * has no backing persistence model yet - see the route comment on
     * GET /api/students/me in server.js.
     *
     * @param {object} data - Parsed response body.
     * @returns {void}
     */
    function renderBilling(data) {
        const { billing } = data;
        const total = billing.fees.reduce((sum, fee) => sum + (Number(fee.amount) || 0), 0);

        document.getElementById('billingBalance').textContent = formatCurrency(billing.balanceDue);
        document.getElementById('billingStatusText').textContent = billing.status;
        document.getElementById('billingStatus').className = `status-text status-text--${Number(billing.balanceDue) > 0 ? 'warn' : 'ok'}`;
        document.getElementById('billingFeeBar').innerHTML = feeBarHtml(billing.fees);
        document.getElementById('billingFeesTitle').textContent = `Assessment of fees (${data.currentTerm})`;

        document.getElementById('billingFeesTableBody').innerHTML = billing.fees.length
            ? billing.fees.map((fee, index) => `
                <tr>
                    <td data-label=""><span class="fee-name"><span class="legend-dot fee-${(index % FEE_TONE_COUNT) + 1}" aria-hidden="true"></span>${escapeHtml(fee.type)}</span></td>
                    <td class="num" data-label="Amount">${formatCurrency(fee.amount)}</td>
                </tr>`).join('')
              + `<tr class="row-total"><td data-label="">Total assessment</td><td class="num" data-label="Amount">${formatCurrency(total)}</td></tr>`
            : '<tr><td colspan="2">No fees assessed.</td></tr>';

        document.getElementById('billingPaymentsTableBody').innerHTML = billing.payments.length
            ? billing.payments.map(payment => `
                <tr>
                    <td data-label="">${escapeHtml(formatDate(payment.date))}</td>
                    <td data-label="OR Number">${escapeHtml(payment.orNumber)}</td>
                    <td class="num" data-label="Amount">${formatCurrency(payment.amount)}</td>
                    <td data-label="Description">${escapeHtml(payment.description)}</td>
                </tr>`).join('')
            : '<tr><td colspan="4">No payments on file.</td></tr>';
    }

    /**
     * Populates the Clearance Status section. Like Schedule and Billing,
     * this has no backing persistence model yet - see the route comment on
     * GET /api/students/me in server.js.
     *
     * @param {object} data - Parsed response body.
     * @returns {void}
     */
    function renderClearance(data) {
        const rows = data.clearance;
        const cleared = rows.filter(row => clearanceTone(row.status) === 'ok').length;

        document.getElementById('clearanceSummary').textContent = rows.length
            ? `${cleared} of ${rows.length} offices cleared`
            : 'No clearance records on file.';
        document.getElementById('clearanceBar').innerHTML = clearanceBarHtml(rows);

        document.getElementById('clearanceTableBody').innerHTML = rows.length
            ? rows.map(row => {
                const tone = clearanceTone(row.status);
                return `
                <tr>
                    <td data-label="">${escapeHtml(row.requirement)}</td>
                    <td data-label="Office">${escapeHtml(row.office)}</td>
                    <td data-label="Status"><span class="pill pill--${tone}">${tone === 'ok' ? icon('check') : ''}${escapeHtml(row.status)}</span></td>
                </tr>`;
            }).join('')
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
                ['home', renderHome],
                ['courses', renderCourses],
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
