const loginForm = document.getElementById('loginForm');
const loginBtn = document.querySelector('.login-btn');
const messageBox = document.getElementById('loginMessage');

// ==========================================
// DEVICE FINGERPRINTING MODULE
// ==========================================
// Generates a unique hardware and software signature to persist tracking
// even if the user alters their IP address via VPNs or proxy servers.
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

// Displays dynamic status messages to the user interface
function showMessage(text, type) {
    messageBox.innerText = text;
    messageBox.className = "login-message msg-" + type;
    messageBox.style.display = "block";
}

// This one script is shared by both login pages (index.html and
// admin_login.html both load it via <script src="script.js">). Each
// page's <body data-portal="student|admin"> declares which audience it's
// for, so the same submit handler below can enforce that boundary
// without needing two near-duplicate copies of this file.
const expectedPortal = document.body.dataset.portal;

// Intercepts the form submission to inject security protocols
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

        // x-user / x-role are gone — the backend no longer trusts client-supplied
        // identity claims at all. x-device-id stays: it's pre-auth telemetry for
        // the behavioral layer, not an identity assertion.
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
            // The credentials were valid, but that alone isn't enough here:
            // check the role the *server* returned against the role this
            // specific page promised. Without this, "separate portals" would
            // only be skin-deep — a student's real credentials would still
            // quietly work on the admin login form. Mirrors the same
            // admin-vs-everyone-else bucketing the redirect below already
            // uses, so an unrecognized non-admin role still lands correctly
            // on the student portal instead of being falsely rejected.
            if (expectedPortal === 'admin' && data.role !== 'admin') {
                showMessage("This portal is for administrators only. Please use the correct login page for your account.", "error");
                return;
            }
            if (expectedPortal === 'student' && data.role === 'admin') {
                showMessage("This portal is for students only. Please use the Admin Portal to sign in.", "error");
                return;
            }

            // Persist the verified session. Every future authenticated request
            // reads this back out and sends it as Authorization: Bearer <token> —
            // nothing about identity is ever inferred from a header again.
            localStorage.setItem('authToken', data.token);
            localStorage.setItem('userEmail', emailValue);

            showMessage("SUCCESS: " + data.message, "success");
            setTimeout(() => {
                // Still driven by the server's own role claim, not by which
                // page hosted the form — the portal check above only decides
                // whether to proceed at all; it never picks the destination.
                window.location.href = (data.role === 'admin') ? "admin_dashboard.html" : "student_dashboard.html";
            }, 1000);

        } else if (response.status === 401) {
            // Wrong credentials on the login endpoint itself — not a stale-token
            // case, so this just shows an error rather than redirecting anywhere.
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
