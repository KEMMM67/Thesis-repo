const loginForm = document.getElementById('loginForm');
const loginBtn = document.querySelector('.login-btn');
const messageBox = document.getElementById('loginMessage');

/**
 * Derives a stable per-device identifier from browser/hardware
 * characteristics, so the behavioral security layer can track a device
 * across requests even if its IP address changes (e.g. via a VPN).
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
 * Displays a status message in the login form's message box.
 *
 * @param {string} text - Message to display.
 * @param {string} type - Message style variant (e.g. "error", "success", "warning").
 * @returns {void}
 */
function showMessage(text, type) {
    messageBox.innerText = text;
    messageBox.className = "login-message msg-" + type;
    messageBox.style.display = "block";
}

// This file is shared by both login pages; each page's
// <body data-portal="student|admin"> declares its audience so a single
// submit handler can enforce the portal boundary below.
const expectedPortal = document.body.dataset.portal;

loginForm.addEventListener('submit', async function(event) {
    event.preventDefault();

    const emailValue = document.getElementById('email').value;
    const passwordValue = document.getElementById('password').value;

    if (!emailValue || !passwordValue) {
        showMessage("Please enter both email and password.", "error");
        return;
    }

    try {
        const deviceId = await getDeviceFingerprint();
        console.log("Device Signature Acquired:", deviceId);

        // x-device-id is pre-auth telemetry for the behavioral layer, not an
        // identity assertion; the server never trusts client-supplied identity.
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
            // Valid credentials alone are not sufficient: the role the server
            // returned must match the role this specific page promised, or a
            // student's real credentials would silently work on the admin form.
            if (expectedPortal === 'admin' && data.role !== 'admin') {
                showMessage("This portal is for administrators only. Please use the correct login page for your account.", "error");
                return;
            }
            if (expectedPortal === 'student' && data.role === 'admin') {
                showMessage("This portal is for students only. Please use the Admin Portal to sign in.", "error");
                return;
            }

            // Every subsequent authenticated request reads this back and sends
            // it as Authorization: Bearer <token>.
            localStorage.setItem('authToken', data.token);
            localStorage.setItem('userEmail', emailValue);

            showMessage("SUCCESS: " + data.message, "success");
            setTimeout(() => {
                window.location.href = (data.role === 'admin') ? "admin_dashboard.html" : "student_dashboard.html";
            }, 1000);

        } else if (response.status === 401) {
            showMessage("Error: " + data.message, "error");

        } else if (response.status === 429) {
            showMessage("SECURITY WARNING: " + data.message, "warning");
            loginBtn.disabled = true;
            loginBtn.style.backgroundColor = "#555";

            let timeLeft = data.retryAfter || 15;

            const timer = setInterval(() => {
                loginBtn.innerText = `Please wait ${timeLeft}s...`;
                timeLeft--;

                if (timeLeft < 0) {
                    clearInterval(timer);
                    loginBtn.disabled = false;
                    loginBtn.style.backgroundColor = "";
                    loginBtn.innerText = "Login";
                    messageBox.style.display = "none";
                }
            }, 1000);

        } else if (response.status === 403) {
            showMessage("🚨 " + data.message, "error");
            loginBtn.innerText = "DEVICE BLOCKED";
            loginBtn.disabled = true;
            loginBtn.style.backgroundColor = "black";

            setTimeout(() => {
                window.location.reload();
            }, 3000);
        }

    } catch (error) {
        console.error("Framework Connection Error:", error);
        showMessage("Cannot establish connection to the Security Architecture.", "error");
    }
});
