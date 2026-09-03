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

/** Email address currently awaiting OTP verification, set by showOtpStep() (called from the login form's submit handler below) once POST /api/login responds with `requireOtp: true`. Cleared whenever the OTP step is left. */
let pendingOtpEmail = null;

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
 * Displays a status message in the given message box.
 *
 * @param {HTMLElement} box - Message box element (loginMessage or otpMessage).
 * @param {string} text - Message to display.
 * @param {string} type - Message style variant ("error", "success", "warning").
 * @returns {void}
 */
function showMessage(box, text, type) {
    box.innerText = text;
    box.className = "login-message msg-" + type;
    box.style.display = "block";
}

/**
 * Switches the page from the OTP step back to the credentials step,
 * restoring the form to its pre-submission state. Used both by the
 * "Back to login" button and on initial page load.
 *
 * @returns {void}
 */
function showCredentialsStep() {
    pendingOtpEmail = null;
    otpForm.style.display = "none";
    otpInput.value = "";
    otpMessage.style.display = "none";
    loginForm.style.display = "block";
    backToStudentLink.style.display = "block";
    testAccountsNote.style.display = "block";
    document.getElementById('password').value = "";
    loginMessage.style.display = "none";
}

/**
 * Switches the page from the credentials step to the OTP step after
 * POST /api/login responds with `requireOtp: true`.
 *
 * @param {string} email - Admin email the code was sent to, for display and for the POST /api/verify-otp body.
 * @returns {void}
 */
function showOtpStep(email) {
    pendingOtpEmail = email;
    loginForm.style.display = "none";
    backToStudentLink.style.display = "none";
    testAccountsNote.style.display = "none";
    otpEmailDisplay.innerText = email;
    otpForm.style.display = "block";
    otpInput.focus();
}

/**
 * Disables `button` and counts down `seconds` on its label, matching the
 * cadence of a WEVA THROTTLE (HTTP 429) verdict - see
 * core/mitigation.js#applyMitigation. Re-enables the button, restores its
 * label, and hides `messageBox` once the countdown reaches zero.
 *
 * @param {HTMLButtonElement} button - Button to disable during the countdown.
 * @param {HTMLElement} messageBox - Message box to hide once the countdown ends.
 * @param {string} idleLabel - Button label to restore when the countdown ends.
 * @param {number} seconds - Countdown length in seconds.
 * @returns {void}
 */
function startThrottleCountdown(button, messageBox, idleLabel, seconds) {
    button.disabled = true;
    button.style.backgroundColor = "#555";

    let timeLeft = seconds;
    const timer = setInterval(() => {
        button.innerText = `Please wait ${timeLeft}s...`;
        timeLeft--;

        if (timeLeft < 0) {
            clearInterval(timer);
            button.disabled = false;
            button.style.backgroundColor = "";
            button.innerText = idleLabel;
            messageBox.style.display = "none";
        }
    }, 1000);
}

/**
 * Locks `button` after a WEVA BLOCK verdict (HTTP 403) and reloads the
 * page shortly after, matching core/mitigation.js#applyMitigation's
 * temporary-block behavior. A full reload is used (rather than resetting
 * just the OTP step) so the page re-initializes from a clean slate
 * regardless of which step was blocked.
 *
 * @param {HTMLButtonElement} button - Button to lock.
 * @returns {void}
 */
function lockDeviceBlocked(button) {
    button.innerText = "DEVICE BLOCKED";
    button.disabled = true;
    button.style.backgroundColor = "black";
    setTimeout(() => window.location.reload(), 3000);
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

    try {
        const deviceId = await getDeviceFingerprint();

        // x-device-id is pre-auth telemetry for the behavioral layer, not
        // an identity assertion; the server never trusts client-supplied
        // identity.
        const response = await fetch('http://localhost:3000/api/login', {
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
                return;
            }

            localStorage.setItem('authToken', data.token);
            localStorage.setItem('userEmail', emailValue);
            showMessage(loginMessage, "SUCCESS: " + data.message, "success");
            setTimeout(() => { window.location.href = "admin_dashboard.html"; }, 1000);

        } else if (response.status === 401) {
            showMessage(loginMessage, "Error: " + data.message, "error");

        } else if (response.status === 429) {
            showMessage(loginMessage, "SECURITY WARNING: " + data.message, "warning");
            startThrottleCountdown(loginBtn, loginMessage, "Login", data.retryAfter || 15);

        } else if (response.status === 403) {
            showMessage(loginMessage, "🚨 " + data.message, "error");
            lockDeviceBlocked(loginBtn);

        } else {
            showMessage(loginMessage, "Error: " + (data.message || "Login failed."), "error");
        }

    } catch (error) {
        console.error("Framework Connection Error:", error);
        showMessage(loginMessage, "Cannot establish connection to the Security Architecture.", "error");
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

    try {
        const deviceId = await getDeviceFingerprint();

        const response = await fetch('http://localhost:3000/api/verify-otp', {
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
            setTimeout(() => { window.location.href = "admin_dashboard.html"; }, 1000);

        } else if (response.status === 401) {
            // Server distinguishes "Invalid OTP" from "OTP has expired..." -
            // see controllers/authController.js#verifyOtp - and both display
            // as-is here.
            showMessage(otpMessage, data.message, "error");

        } else if (response.status === 429) {
            showMessage(otpMessage, "SECURITY WARNING: " + data.message, "warning");
            startThrottleCountdown(verifyBtn, otpMessage, "Verify", data.retryAfter || 15);

        } else if (response.status === 403) {
            showMessage(otpMessage, "🚨 " + data.message, "error");
            lockDeviceBlocked(verifyBtn);

        } else {
            showMessage(otpMessage, "Error: " + (data.message || "Verification failed."), "error");
        }

    } catch (error) {
        console.error("Framework Connection Error:", error);
        showMessage(otpMessage, "Cannot establish connection to the Security Architecture.", "error");
    }
});

backToLoginBtn.addEventListener('click', showCredentialsStep);
