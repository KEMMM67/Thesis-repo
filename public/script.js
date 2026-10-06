const loginForm = document.getElementById('loginForm');
const loginBtn = document.querySelector('.login-btn');
const messageBox = document.getElementById('loginMessage');

const LOGIN_IDLE_LABEL = 'Login';

/** Where this browser's device ID is kept. One origin, one localStorage: every page of both portals shares it. */
const DEVICE_ID_KEY = 'sis.deviceId';
const DEVICE_ID_FORMAT = /^DEV-[0-9a-f]{32}$/;
let pageDeviceId = null;

/**
 * Returns this browser's device ID for WEVA's device layer (the x-device-id
 * header): "DEV-" and 32 random hex digits, created on first use and kept in
 * localStorage, so it stays the same across visits and across every page.
 * public/admin_login.js and both dashboards keep identical copies.
 *
 * Why random. It used to be a hash of the user agent, language, color depth,
 * screen size and timezone - identical on every PC of a computer lab, and on
 * every phone of one model running the same browser version. Everyone who
 * shared a value shared one failure history, and the device layer counts
 * refused attempts too and keeps them until a success settles them. Worked
 * example: four students at identical lab PCs have each mistyped once and
 * not yet retyped. The next student's first attempt scores
 * 2 x 2 x (1 + 4 x 0.5) x 5 = 60 - THROTTLE - and that refusal is recorded
 * as a fifth failure. The four then retype correctly, but are refused before
 * their passwords are checked, so nothing settles and the whole lab climbs
 * to BLOCK together. Random IDs never collide, which is the one property
 * the device layer needs from them.
 *
 * Nothing is lost: the header was always chosen by the client, so it was
 * never a security boundary. A bot that rotates IDs is stopped by the IP
 * layer, and signed-in requests by the account layer
 * (middleware/securityMiddleware.js). And unlike a fingerprint, clearing the
 * site's data resets it.
 *
 * crypto.getRandomValues() rather than crypto.randomUUID(), which browsers
 * only provide over HTTPS: a LAN demo served over plain HTTP must work too.
 *
 * @returns {string} e.g. "DEV-9f86d081884c7d659a2feaa0c55ad015".
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
 * Displays a status message in the login form's message box, built from
 * DOM nodes (not innerHTML) so the optional calmer `subtext` line can sit
 * under the primary message without any string-concatenation injection
 * risk.
 *
 * @param {string} text - Primary message to display.
 * @param {string} type - Message style variant ("error", "success", "warning").
 * @param {string} [subtext] - Optional calmer secondary line, styled quieter than `text` - used for the BLOCK/THROTTLE "this is automatic and temporary" note below.
 * @returns {void}
 */
function showMessage(text, type, subtext) {
    messageBox.innerHTML = '';
    const main = document.createElement('div');
    main.textContent = text;
    messageBox.appendChild(main);
    if (subtext) {
        const sub = document.createElement('div');
        sub.className = 'login-message-subtext';
        sub.textContent = subtext;
        messageBox.appendChild(sub);
    }
    messageBox.className = "login-message msg-" + type;
    messageBox.style.display = "block";
}

/**
 * Toggles the login button's loading state. Disabling it immediately on
 * submit - before the fetch even starts - prevents spam-clicking Login
 * while an admin's POST /api/login is still waiting on Nodemailer to
 * dispatch the OTP email (see controllers/authController.js#beginOtpChallenge):
 * without this, each extra click fires another full login request, sending
 * another OTP email and adding another data point to WEVA's request-velocity
 * score for a click the user only made because the button hadn't visibly
 * responded yet.
 *
 * @param {boolean} isLoading
 * @returns {void}
 */
function setLoading(isLoading) {
    if (isLoading) {
        loginBtn.disabled = true;
        loginBtn.style.backgroundColor = "";
        loginBtn.innerHTML = '<span class="btn-spinner" aria-hidden="true"></span>Logging in...';
    } else {
        loginBtn.disabled = false;
        loginBtn.style.backgroundColor = "";
        loginBtn.innerHTML = LOGIN_IDLE_LABEL;
    }
}

/**
 * Disables `button` and counts down `seconds` on its label, matching
 * either a WEVA THROTTLE (429) or BLOCK (403) verdict - see
 * core/mitigation.js#applyMitigation, which now reports the lockout's real
 * remaining time as `retryAfterSeconds`/`retryAfter` instead of leaving the
 * frontend to guess one. Re-enables the button, restores `idleLabel`, and
 * hides `messageBox` once the countdown reaches zero - no page reload
 * involved, unlike this function's predecessor.
 *
 * @param {HTMLButtonElement} button
 * @param {HTMLElement} box - Message box to hide once the countdown ends.
 * @param {string} idleLabel
 * @param {number} seconds
 * @param {string} lockColor - Button background while counting down (throttle grey vs. block black).
 * @returns {void}
 */
function startCountdown(button, box, idleLabel, seconds, lockColor) {
    button.disabled = true;
    button.style.backgroundColor = lockColor;

    let timeLeft = Math.max(0, Math.round(seconds) || 0);

    const render = () => { button.innerText = `Please wait ${timeLeft}s...`; };
    render();

    const timer = setInterval(() => {
        timeLeft--;
        if (timeLeft < 0) {
            clearInterval(timer);
            button.disabled = false;
            button.style.backgroundColor = "";
            button.innerText = idleLabel;
            box.style.display = "none";
            return;
        }
        render();
    }, 1000);
}

// This file is shared by both login pages; each page's
// <body data-portal="student|admin"> declares its audience so a single
// submit handler can enforce the portal boundary below.
const expectedPortal = document.body.dataset.portal;

// Where each portal keeps its session in localStorage, by the role it is
// for. Both portals share one origin, so one localStorage - and under the
// shared keys they used to have (authToken, userEmail), signing in here
// replaced an admin's token signed in on another tab. The dashboards read
// these same keys (public/student_dashboard.js, public/admin_dashboard.js).
const SESSION_KEYS = {
    student: { token: 'sis.student.token', email: 'sis.student.email' },
    admin: { token: 'sis.admin.token', email: 'sis.admin.email' }
};

loginForm.addEventListener('submit', async function(event) {
    event.preventDefault();

    const emailValue = document.getElementById('email').value;
    const passwordValue = document.getElementById('password').value;

    if (!emailValue || !passwordValue) {
        showMessage("Please enter both email and password.", "error");
        return;
    }

    setLoading(true);

    try {
        const deviceId = getDeviceId();
        console.log("Device ID:", deviceId);

        // x-device-id is pre-auth telemetry for the behavioral layer, not an
        // identity assertion; the server never trusts client-supplied identity.
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-device-id': deviceId
            },
            body: JSON.stringify({ email: emailValue, password: passwordValue })
        });

        const data = await response.json();

        if (response.ok) {
            // This shared page has no OTP form - only public/admin_login.js
            // does. An admin account can still authenticate here (POST
            // /api/login doesn't know which page called it), and a correct
            // password for one advances it to the OTP challenge just like
            // on the dedicated admin page (see
            // controllers/authController.js#beginOtpChallenge) - but with no
            // OTP UI to show, that response has no `token` to store. Without
            // this check, the code below would fall straight through to
            // storing an undefined token and redirect to a dashboard the
            // browser can never actually authenticate against.
            if (data.requireOtp) {
                showMessage("This account requires a verification code. Please sign in from the Admin Portal instead.", "error");
                setLoading(false);
                return;
            }

            // Valid credentials alone are not sufficient: the role the server
            // returned must match the role this specific page promised, or a
            // student's real credentials would silently work on the admin form.
            if (expectedPortal === 'admin' && data.role !== 'admin') {
                showMessage("This portal is for administrators only. Please use the correct login page for your account.", "error");
                setLoading(false);
                return;
            }
            if (expectedPortal === 'student' && data.role === 'admin') {
                showMessage("This portal is for students only. Please use the Admin Portal to sign in.", "error");
                setLoading(false);
                return;
            }

            // Every subsequent authenticated request reads this back and sends
            // it as Authorization: Bearer <token> - stored under the keys of
            // the dashboard about to be opened, and the old shared keys
            // cleared so a stale token does not linger in storage.
            const session = SESSION_KEYS[data.role === 'admin' ? 'admin' : 'student'];
            localStorage.setItem(session.token, data.token);
            localStorage.setItem(session.email, emailValue);
            localStorage.removeItem('authToken');
            localStorage.removeItem('userEmail');

            showMessage("SUCCESS: " + data.message, "success");
            // Left disabled/loading deliberately: the page is navigating away.
            setTimeout(() => {
                window.location.href = (data.role === 'admin') ? "admin_dashboard.html" : "student_dashboard.html";
            }, 1000);

        } else if (response.status === 401) {
            showMessage("Error: " + data.message, "error");
            setLoading(false);

        } else if (response.status === 429) {
            showMessage(
                "SECURITY WARNING: " + data.message,
                "warning",
                "This is an automatic, temporary safety measure - it lifts on its own; no need to contact support."
            );
            startCountdown(loginBtn, messageBox, LOGIN_IDLE_LABEL, data.retryAfter || 15, "#555");

        } else if (response.status === 403) {
            showMessage(
                "🚨 " + data.message,
                "error",
                "This is an automatic, temporary safety measure - it lifts on its own; no need to contact support."
            );
            // Real countdown driven by the server's own retryAfterSeconds
            // (core/mitigation.js) - previously this reloaded the page after
            // a hardcoded 3 seconds, which had nothing to do with the real
            // ~60-second lockout and just let a confused user retry straight
            // into another BLOCK.
            startCountdown(loginBtn, messageBox, LOGIN_IDLE_LABEL, data.retryAfterSeconds || 60, "black");

        } else {
            showMessage("Error: " + (data.message || "Login failed."), "error");
            setLoading(false);
        }

    } catch (error) {
        console.error("Framework Connection Error:", error);
        showMessage("Cannot establish connection to the Security Architecture.", "error");
        setLoading(false);
    }
});
