/**
 * @fileoverview Admin Portal login flow: password step, then a mandatory
 * OTP (one-time code) step for admin accounts - see
 * controllers/authController.js for the server-side design this mirrors.
 *
 * Dedicated to admin_login.html rather than shared with the student/signup
 * pages (public/script.js): only admin accounts go through the OTP step,
 * so folding it into the shared script would mean every page loading it
 * carries OTP-handling code that can only ever run on this one page. A
 * handful of small helpers below (getDeviceFingerprint, showMessage) are
 * intentionally duplicated from script.js rather than imported, matching
 * the existing precedent in public/admin_dashboard.js of each dashboard
 * script being self-contained.
 */

const loginForm = document.getElementById('loginForm');
const loginBtn = loginForm.querySelector('.login-btn');
const loginMessage = document.getElementById('loginMessage');

const otpForm = document.getElementById('otpForm');
const otpInput = document.getElementById('otp');
const otpEmailDisplay = document.getElementById('otpEmailDisplay');
const verifyBtn = otpForm.querySelector('.login-btn');
const otpMessage = document.getElementById('otpMessage');
const backToLoginBtn = document.getElementById('backToLoginBtn');

// Chrome hidden alongside the credentials form while the OTP step is
// showing - neither is relevant mid-verification, and re-showing them is
// part of restoring the pre-login state in showCredentialsStep() below.
const backToStudentLink = document.getElementById('backToStudentLink');
const testAccountsNote = document.getElementById('testAccountsNote');

const LOGIN_IDLE_LABEL = 'Login';
const VERIFY_IDLE_LABEL = 'Verify';
const RESEND_IDLE_LABEL = 'Resend code';

// Calmer secondary line shown under a BLOCK/THROTTLE message - the primary
// line is deliberately alarming ("CRITICAL THREAT...", straight from
// core/mitigation.js), which is correct for an actual attacker but can read
// as frightening to a legitimate admin who just mistyped a password or code
// a few times. This note doesn't excuse the block; it just tells a genuine
// user what to expect (it lifts on its own) instead of leaving them to
// wonder whether their account is now in trouble.
const AUTOMATIC_SAFETY_NOTE = "This is an automatic, temporary safety measure - it lifts on its own; no need to contact support.";

/**
 * "Resend code" control, injected here rather than added to
 * admin_login.html so this feature stays self-contained in this file.
 * Placed next to "Back to login" inside the OTP form - same `.link-btn`
 * treatment, same visual weight as the other secondary action on this step.
 */
const resendOtpBtn = document.createElement('button');
resendOtpBtn.type = 'button';
resendOtpBtn.id = 'resendOtpBtn';
resendOtpBtn.className = 'link-btn';
resendOtpBtn.textContent = RESEND_IDLE_LABEL;
backToLoginBtn.insertAdjacentElement('afterend', resendOtpBtn);

/** Email address currently awaiting OTP verification, set by showOtpStep() (called from the login form's submit handler below) once POST /api/login responds with `requireOtp: true`. Cleared whenever the OTP step is left. */
let pendingOtpEmail = null;

/**
 * Password that produced the current pending OTP challenge, kept only in
 * memory (never persisted) so "Resend code" below can replay the exact
 * same POST /api/login call that dispatches a fresh OTP - there is no
 * separate "resend" endpoint; a new code is simply whatever
 * beginOtpChallenge() sends on the next successful password check (see
 * controllers/authController.js). Cleared together with pendingOtpEmail
 * whenever the OTP step is left.
 */
let pendingOtpPassword = null;

/** Interval id of whichever countdown (THROTTLE or BLOCK) is currently running, so a step change (e.g. "Back to login") can cancel a stale timer instead of leaving it to fire against a hidden form later. */
let activeCountdownTimer = null;

/**
 * Derives a stable per-device identifier from browser/hardware
 * characteristics, so the behavioral security layer can track a device
 * across requests even if its IP address changes (e.g. via a VPN). Used
 * for both POST /api/login and POST /api/verify-otp so WEVA attributes
 * both steps of one login to the same device (see core/monitor.js).
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
 * Displays a status message in the given message box, built from DOM nodes
 * (not innerHTML) so the optional calmer `subtext` line can sit under the
 * primary message without any string-concatenation injection risk.
 *
 * @param {HTMLElement} box - Message box element (loginMessage or otpMessage).
 * @param {string} text - Message to display.
 * @param {string} type - Message style variant ("error", "success", "warning").
 * @param {string} [subtext] - Optional calmer secondary line, styled quieter than `text`.
 * @returns {void}
 */
function showMessage(box, text, type, subtext) {
    box.innerHTML = '';
    const main = document.createElement('div');
    main.textContent = text;
    box.appendChild(main);
    if (subtext) {
        const sub = document.createElement('div');
        sub.className = 'login-message-subtext';
        sub.textContent = subtext;
        box.appendChild(sub);
    }
    box.className = "login-message msg-" + type;
    box.style.display = "block";
}

/**
 * Toggles a button's loading state: disabled with a spinner + `loadingLabel`
 * while `isLoading`, restored to `idleLabel` otherwise. Disabling
 * immediately on submit - before the fetch even starts - is what stops
 * spam-clicking Login from firing multiple POST /api/login calls while
 * Nodemailer is still dispatching the OTP email (see
 * controllers/authController.js#beginOtpChallenge): each extra click would
 * otherwise send another OTP email and add another data point to WEVA's
 * request-velocity score for a click the user only made because the button
 * hadn't visibly responded yet.
 *
 * @param {HTMLButtonElement} button
 * @param {boolean} isLoading
 * @param {string} loadingLabel - Text shown next to the spinner while loading.
 * @param {string} [idleLabel] - Label restored when isLoading is false. Required unless isLoading is true.
 * @returns {void}
 */
function setLoading(button, isLoading, loadingLabel, idleLabel) {
    button.style.backgroundColor = "";
    if (isLoading) {
        button.disabled = true;
        button.innerHTML = `<span class="btn-spinner" aria-hidden="true"></span>${loadingLabel}`;
    } else {
        button.disabled = false;
        button.innerHTML = idleLabel;
    }
}

/**
 * Disables `button` and counts down `seconds` on its label, matching either
 * a WEVA THROTTLE (429) or BLOCK (403) verdict - see
 * core/mitigation.js#applyMitigation, which now reports the lockout's real
 * remaining time as `retryAfterSeconds`/`retryAfter` instead of leaving the
 * frontend to guess one. Re-enables `button` (and every entry in
 * `alsoDisable`), restores their labels, and hides `box` once the countdown
 * reaches zero - no page reload involved, unlike this function's
 * predecessor (lockDeviceBlocked()).
 *
 * Cancels any previously-running countdown first: without this, leaving a
 * step mid-countdown (e.g. clicking "Back to login" during a lockout) and
 * later returning to a fresh one could leave two timers fighting over the
 * same buttons.
 *
 * @param {HTMLButtonElement} button - Primary button to disable and animate.
 * @param {HTMLElement} box - Message box to hide once the countdown ends.
 * @param {string} idleLabel - Label restored on `button` once the countdown ends.
 * @param {number} seconds - Countdown length in seconds.
 * @param {string} lockColor - `button`'s background while counting down (throttle grey vs. block black).
 * @param {Array<{element: HTMLButtonElement, idleLabel: string}>} [alsoDisable] - Secondary buttons (e.g. "Resend code") that share the same lockout and should stay disabled for the same duration, restored to their own idle labels at the end.
 * @returns {void}
 */
function startCountdown(button, box, idleLabel, seconds, lockColor, alsoDisable = []) {
    if (activeCountdownTimer) clearInterval(activeCountdownTimer);

    button.disabled = true;
    button.style.backgroundColor = lockColor;
    alsoDisable.forEach(({ element }) => {
        element.disabled = true;
        element.innerHTML = 'Locked';
    });

    let timeLeft = Math.max(0, Math.round(seconds) || 0);
    const render = () => { button.innerText = `Please wait ${timeLeft}s...`; };
    render();

    activeCountdownTimer = setInterval(() => {
        timeLeft--;
        if (timeLeft < 0) {
            clearInterval(activeCountdownTimer);
            activeCountdownTimer = null;
            button.disabled = false;
            button.style.backgroundColor = "";
            button.innerText = idleLabel;
            alsoDisable.forEach(({ element, idleLabel: elIdle }) => {
                element.disabled = false;
                element.innerHTML = elIdle;
            });
            box.style.display = "none";
            return;
        }
        render();
    }, 1000);
}

/**
 * Switches the page from the OTP step back to the credentials step,
 * restoring the form to its pre-submission state. Used both by the
 * "Back to login" button and on initial page load.
 *
 * @returns {void}
 */
function showCredentialsStep() {
    if (activeCountdownTimer) { clearInterval(activeCountdownTimer); activeCountdownTimer = null; }

    pendingOtpEmail = null;
    pendingOtpPassword = null;
    otpForm.style.display = "none";
    otpInput.value = "";
    otpMessage.style.display = "none";
    setLoading(verifyBtn, false, null, VERIFY_IDLE_LABEL);
    setLoading(resendOtpBtn, false, null, RESEND_IDLE_LABEL);
    loginForm.style.display = "block";
    backToStudentLink.style.display = "block";
    testAccountsNote.style.display = "block";
    document.getElementById('password').value = "";
    loginMessage.style.display = "none";
    setLoading(loginBtn, false, null, LOGIN_IDLE_LABEL);
}

/**
 * Switches the page from the credentials step to the OTP step after
 * POST /api/login responds with `requireOtp: true`.
 *
 * @param {string} email - Admin email the code was sent to, for display and for the POST /api/verify-otp body.
 * @returns {void}
 */
function showOtpStep(email) {
    if (activeCountdownTimer) { clearInterval(activeCountdownTimer); activeCountdownTimer = null; }

    pendingOtpEmail = email;
    loginForm.style.display = "none";
    backToStudentLink.style.display = "none";
    testAccountsNote.style.display = "none";
    otpEmailDisplay.innerText = email;
    setLoading(verifyBtn, false, null, VERIFY_IDLE_LABEL);
    setLoading(resendOtpBtn, false, null, RESEND_IDLE_LABEL);
    otpForm.style.display = "block";
    otpInput.focus();
}

showCredentialsStep();

loginForm.addEventListener('submit', async function (event) {
    event.preventDefault();

    const emailValue = document.getElementById('email').value;
    const passwordValue = document.getElementById('password').value;

    if (!emailValue || !passwordValue) {
        showMessage(loginMessage, "Please enter both email and password.", "error");
        return;
    }

    // Loading state: disabled immediately, before the fetch even starts -
    // see setLoading()'s doc comment for why this matters specifically on
    // this button (a slow Nodemailer OTP dispatch sitting behind it).
    setLoading(loginBtn, true, "Sending Code...");

    try {
        const deviceId = await getDeviceFingerprint();

        // x-device-id is pre-auth telemetry for the behavioral layer, not
        // an identity assertion; the server never trusts client-supplied
        // identity.
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
            if (data.requireOtp) {
                pendingOtpPassword = passwordValue;
                showMessage(loginMessage, data.message || "OTP sent to email.", "success");
                showOtpStep(data.email);
                return;
            }

            // No OTP challenge means the server issued a token directly -
            // only expected for a non-admin account (this codebase's OTP
            // step is admin-only; see controllers/authController.js).
            // Valid credentials alone are not enough here: the role must
            // match the portal, or a student's real credentials would
            // silently work on the admin form.
            if (data.role !== 'admin') {
                showMessage(loginMessage, "This portal is for administrators only. Please use the correct login page for your account.", "error");
                setLoading(loginBtn, false, null, LOGIN_IDLE_LABEL);
                return;
            }

            localStorage.setItem('authToken', data.token);
            localStorage.setItem('userEmail', emailValue);
            showMessage(loginMessage, "SUCCESS: " + data.message, "success");
            // Left disabled/loading deliberately: the page is navigating away.
            setTimeout(() => { window.location.href = "admin_dashboard.html"; }, 1000);

        } else if (response.status === 401) {
            showMessage(loginMessage, "Error: " + data.message, "error");
            setLoading(loginBtn, false, null, LOGIN_IDLE_LABEL);

        } else if (response.status === 429) {
            showMessage(loginMessage, "SECURITY WARNING: " + data.message, "warning", AUTOMATIC_SAFETY_NOTE);
            startCountdown(loginBtn, loginMessage, LOGIN_IDLE_LABEL, data.retryAfter || 15, "#555");

        } else if (response.status === 403) {
            showMessage(loginMessage, "🚨 " + data.message, "error", AUTOMATIC_SAFETY_NOTE);
            // Real countdown driven by the server's own retryAfterSeconds
            // (core/mitigation.js) - previously this reloaded the page
            // after a hardcoded 3 seconds, unrelated to the real ~60-second
            // lockout, which just let a confused user retry straight into
            // another BLOCK.
            startCountdown(loginBtn, loginMessage, LOGIN_IDLE_LABEL, data.retryAfterSeconds || 60, "black");

        } else {
            showMessage(loginMessage, "Error: " + (data.message || "Login failed."), "error");
            setLoading(loginBtn, false, null, LOGIN_IDLE_LABEL);
        }

    } catch (error) {
        console.error("Framework Connection Error:", error);
        showMessage(loginMessage, "Cannot establish connection to the Security Architecture.", "error");
        setLoading(loginBtn, false, null, LOGIN_IDLE_LABEL);
    }
});

otpForm.addEventListener('submit', async function (event) {
    event.preventDefault();

    const otpValue = otpInput.value.trim();
    if (!/^\d{6}$/.test(otpValue)) {
        showMessage(otpMessage, "Enter the 6-digit code exactly as sent.", "error");
        return;
    }
    if (!pendingOtpEmail) {
        // Defensive only: the OTP form is unreachable without pendingOtpEmail
        // being set by showOtpStep() first.
        showCredentialsStep();
        return;
    }

    setLoading(verifyBtn, true, "Verifying...");

    try {
        const deviceId = await getDeviceFingerprint();

        const response = await fetch('/api/verify-otp', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-device-id': deviceId
            },
            body: JSON.stringify({ email: pendingOtpEmail, otp: otpValue })
        });

        const data = await response.json();

        if (response.ok && data.token) {
            localStorage.setItem('authToken', data.token);
            localStorage.setItem('userEmail', pendingOtpEmail);
            showMessage(otpMessage, "SUCCESS: " + data.message, "success");
            // Left disabled/loading deliberately: the page is navigating away.
            setTimeout(() => { window.location.href = "admin_dashboard.html"; }, 1000);

        } else if (response.status === 401) {
            // Server distinguishes "Invalid OTP" from "OTP has expired..." -
            // see controllers/authController.js#verifyOtp - and both display
            // as-is here.
            showMessage(otpMessage, data.message, "error");
            setLoading(verifyBtn, false, null, VERIFY_IDLE_LABEL);

        } else if (response.status === 429) {
            showMessage(otpMessage, "SECURITY WARNING: " + data.message, "warning", AUTOMATIC_SAFETY_NOTE);
            startCountdown(verifyBtn, otpMessage, VERIFY_IDLE_LABEL, data.retryAfter || 15, "#555", [{ element: resendOtpBtn, idleLabel: RESEND_IDLE_LABEL }]);

        } else if (response.status === 403) {
            showMessage(otpMessage, "🚨 " + data.message, "error", AUTOMATIC_SAFETY_NOTE);
            startCountdown(verifyBtn, otpMessage, VERIFY_IDLE_LABEL, data.retryAfterSeconds || 60, "black", [{ element: resendOtpBtn, idleLabel: RESEND_IDLE_LABEL }]);

        } else {
            showMessage(otpMessage, data.message || "Verification failed.", "error");
            setLoading(verifyBtn, false, null, VERIFY_IDLE_LABEL);
        }

    } catch (error) {
        console.error("Framework Connection Error:", error);
        showMessage(otpMessage, "Cannot establish connection to the Security Architecture.", "error");
        setLoading(verifyBtn, false, null, VERIFY_IDLE_LABEL);
    }
});

/**
 * Resends the OTP by replaying the exact password check that produced the
 * current one - see pendingOtpPassword's doc comment for why there is no
 * separate resend endpoint. This request runs through the same
 * securityMiddleware/WEVA pipeline as any other POST /api/login call
 * (routes/authRoutes.js), so spamming "Resend" is naturally subject to the
 * same fail-rate scoring as repeated wrong-password attempts - no separate
 * client-side cooldown is invented here beyond the ordinary loading-state
 * disable, since the server already rate-limits this endpoint.
 */
resendOtpBtn.addEventListener('click', async () => {
    if (!pendingOtpEmail || !pendingOtpPassword) {
        showCredentialsStep();
        return;
    }

    setLoading(resendOtpBtn, true, "Sending...");

    try {
        const deviceId = await getDeviceFingerprint();

        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-device-id': deviceId
            },
            body: JSON.stringify({ email: pendingOtpEmail, password: pendingOtpPassword })
        });

        const data = await response.json();

        if (response.ok && data.requireOtp) {
            setLoading(resendOtpBtn, false, null, RESEND_IDLE_LABEL);
            otpInput.value = "";
            otpInput.focus();
            showMessage(otpMessage, `A new code has been sent to ${data.email}.`, "success");

        } else if (response.status === 429) {
            showMessage(otpMessage, "SECURITY WARNING: " + data.message, "warning", AUTOMATIC_SAFETY_NOTE);
            startCountdown(verifyBtn, otpMessage, VERIFY_IDLE_LABEL, data.retryAfter || 15, "#555", [{ element: resendOtpBtn, idleLabel: RESEND_IDLE_LABEL }]);

        } else if (response.status === 403) {
            showMessage(otpMessage, "🚨 " + data.message, "error", AUTOMATIC_SAFETY_NOTE);
            startCountdown(verifyBtn, otpMessage, VERIFY_IDLE_LABEL, data.retryAfterSeconds || 60, "black", [{ element: resendOtpBtn, idleLabel: RESEND_IDLE_LABEL }]);

        } else if (response.status === 401) {
            // The password that started this OTP challenge no longer
            // matches (e.g. changed by an admin elsewhere mid-flow) -
            // there is no code to resend until the user re-authenticates.
            setLoading(resendOtpBtn, false, null, RESEND_IDLE_LABEL);
            showMessage(otpMessage, "Could not resend the code - please log in again.", "error");

        } else {
            setLoading(resendOtpBtn, false, null, RESEND_IDLE_LABEL);
            showMessage(otpMessage, data.message || "Could not resend the code. Please try again.", "error");
        }

    } catch (error) {
        console.error("Framework Connection Error:", error);
        setLoading(resendOtpBtn, false, null, RESEND_IDLE_LABEL);
        showMessage(otpMessage, "Cannot establish connection to the Security Architecture.", "error");
    }
});

backToLoginBtn.addEventListener('click', showCredentialsStep);
