import nodemailer from "nodemailer";

/**
 * @fileoverview Best-effort email notification service.
 *
 * Login alerts are defense-in-depth alongside the WEVA behavioral layer
 * (core/scorer.js, middleware/securityMiddleware.js): WEVA's job is to
 * stop a high-velocity brute-force burst before it succeeds, but it has
 * nothing to say about a *slow*, low-and-slow credential-stuffing attempt
 * that never crosses a velocity threshold yet still lands on the right
 * password eventually. Notifying the account owner on every successful
 * login surfaces exactly that case to the one person positioned to
 * recognize "that wasn't me" and act on it.
 *
 * Every export in this module is written to never *throw* - a
 * misconfigured mail account, an offline SMTP server, or a network
 * timeout is always caught internally and logged rather than propagated.
 *
 * sendLoginAlert() and sendOtpEmail() differ, though, in what they do
 * with that caught failure, because they sit in different places in the
 * login flow. sendLoginAlert() is a supplementary notification sent
 * *after* login has already succeeded, so it stays fire-and-forget and
 * always resolves - a legitimate user must never be locked out of an
 * account they already got into just because an unrelated mail-delivery
 * problem occurred. sendOtpEmail() is different: for an admin account it
 * is the *only* channel carrying the one code that can complete the
 * login (see controllers/authController.js), so silently swallowing a
 * delivery failure there would tell the admin "OTP sent to email" when
 * no code is coming, leaving them stuck with no way to proceed. It is
 * therefore awaited by its caller and resolves to a boolean so the
 * caller can tell the client the truth instead.
 */

/**
 * Nodemailer transporter for Gmail SMTP, authenticated with a Google
 * App Password (not the account's login password - see
 * https://myaccount.google.com/apppasswords). Constructing a transporter
 * does not itself open a connection or validate credentials; both happen
 * lazily on the first sendMail() call, so a bad SMTP_APP_PASSWORD surfaces
 * as a caught error in sendLoginAlert() below, not at server startup.
 *
 * The explicit timeouts matter on hosts that silently drop SMTP traffic -
 * Render's free web services block outbound ports 25/465/587. Nodemailer's
 * defaults would hold an admin's login request open for up to 2 minutes
 * waiting on a connection that can never succeed, until a proxy in front
 * of the app cut it off; with these, it fails in ~10 s and the admin gets
 * a real "could not send verification code" error instead.
 */
const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 20_000,
    auth: {
        user: process.env.SMTP_EMAIL,
        pass: process.env.SMTP_APP_PASSWORD
    }
});

const RESEND_ENDPOINT = "https://api.resend.com/emails";

/**
 * @returns {boolean} Whether any delivery channel is configured: Resend's
 *          HTTPS API (RESEND_API_KEY) or Gmail SMTP (SMTP_EMAIL + SMTP_APP_PASSWORD).
 */
function hasMailConfig() {
    return Boolean(process.env.RESEND_API_KEY || (process.env.SMTP_EMAIL && process.env.SMTP_APP_PASSWORD));
}

/**
 * Sends one email, over Resend's HTTPS API when RESEND_API_KEY is set,
 * otherwise over Gmail SMTP. HTTPS goes out on port 443, which hosts that
 * block SMTP (Render's free tier, above) still allow. Without a verified
 * domain, Resend only delivers from onboarding@resend.dev to the address
 * the Resend account was created with - enough for an admin's own OTP.
 * Throws on failure; the exported senders below catch.
 *
 * @param {{to: string, subject: string, html: string}} message
 * @returns {Promise<void>}
 */
async function deliver({ to, subject, html }) {
    if (process.env.RESEND_API_KEY) {
        const response = await fetch(RESEND_ENDPOINT, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ from: process.env.RESEND_FROM || "SIS Security <onboarding@resend.dev>", to, subject, html }),
            signal: AbortSignal.timeout(10_000)
        });
        if (!response.ok) {
            throw new Error(`Resend responded ${response.status}: ${await response.text()}`);
        }
        return;
    }

    await transporter.sendMail({ from: `"SIS Security" <${process.env.SMTP_EMAIL}>`, to, subject, html });
}

/**
 * Builds the HTML body of a new-login security alert. Styles are inlined
 * throughout rather than placed in a `<style>` block, since most email
 * clients (Gmail's web client included) strip non-inline `<style>` rules.
 *
 * @param {string} userEmail - Email address of the account that signed in.
 * @param {string} ipAddress - Originating IP address of the login.
 * @param {string} timestamp - Human-readable timestamp of the login event.
 * @returns {string} Self-contained HTML email body.
 */
function buildLoginAlertHtml(userEmail, ipAddress, timestamp) {
    return `
    <div style="background-color:#f4f6f9;padding:32px 16px;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;">
        <table role="presentation" width="100%" style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:8px;overflow:hidden;border:1px solid #e2e5ea;">
            <tr>
                <td style="background-color:#8b0000;padding:20px 28px;">
                    <span style="color:#ffffff;font-size:16px;font-weight:700;letter-spacing:0.5px;">STUDENT INFORMATION SYSTEM</span>
                </td>
            </tr>
            <tr>
                <td style="padding:28px;">
                    <h2 style="margin:0 0 12px;font-size:18px;color:#1a1a1a;">New Sign-In to Your Account</h2>
                    <p style="margin:0 0 20px;font-size:14px;line-height:1.6;color:#444;">
                        We detected a successful login to the account <strong>${userEmail}</strong>.
                        If this was you, no action is needed.
                    </p>
                    <table role="presentation" width="100%" style="background:#f8f9fb;border:1px solid #e2e5ea;border-radius:6px;font-size:13px;color:#333;">
                        <tr>
                            <td style="padding:12px 16px;font-weight:600;width:120px;">Time</td>
                            <td style="padding:12px 16px;">${timestamp}</td>
                        </tr>
                        <tr>
                            <td style="padding:12px 16px;font-weight:600;border-top:1px solid #e2e5ea;">IP Address</td>
                            <td style="padding:12px 16px;border-top:1px solid #e2e5ea;">${ipAddress}</td>
                        </tr>
                    </table>
                    <p style="margin:24px 0 0;font-size:13px;line-height:1.6;color:#666;">
                        <strong>Didn't sign in?</strong> Your password may be compromised. Contact your
                        system administrator immediately so the account and device can be reviewed and,
                        if necessary, blocked.
                    </p>
                </td>
            </tr>
            <tr>
                <td style="padding:16px 28px;background:#f8f9fb;border-top:1px solid #e2e5ea;">
                    <span style="font-size:11px;color:#999;">This is an automated security notification. Please do not reply to this email.</span>
                </td>
            </tr>
        </table>
    </div>`;
}

/**
 * Sends a "new login" security alert to the account owner. Fire-and-forget
 * by design: callers should invoke this without `await`ing it so an SMTP
 * round trip never adds latency to the login response, and every failure
 * mode (bad credentials, DNS failure, timeout, provider rejection) is
 * caught here and logged rather than propagated - this function always
 * resolves and never rejects.
 *
 * @param {string} userEmail - Email address of the account that signed in; also the alert recipient.
 * @param {string} ipAddress - Originating IP address of the login attempt.
 * @returns {Promise<void>}
 */
export async function sendLoginAlert(userEmail, ipAddress) {
    if (!hasMailConfig()) {
        console.warn("[emailService] No mail delivery configured (RESEND_API_KEY or SMTP_EMAIL/SMTP_APP_PASSWORD) - skipping login alert.");
        return;
    }

    try {
        const timestamp = new Date().toLocaleString("en-PH", { dateStyle: "full", timeStyle: "long" });

        await deliver({
            to: userEmail,
            subject: "New Sign-In to Your SIS Account",
            html: buildLoginAlertHtml(userEmail, ipAddress, timestamp)
        });

        console.log(`[emailService] Login alert sent to ${userEmail}.`);
    } catch (err) {
        console.error(`[emailService] Failed to send login alert to ${userEmail}:`, err.message);
    }
}

/**
 * Builds the HTML body of a one-time verification code email. Mirrors
 * buildLoginAlertHtml()'s layout (same inline-styled table, same brand
 * header) so the two emails read as one consistent product, but leads
 * with the code itself, large and letter-spaced, since that is the one
 * piece of information the recipient actually needs to act on quickly.
 *
 * @param {string} otpCode - The 6-digit numeric code to display.
 * @param {number} ttlMinutes - Minutes until the code expires, for display only.
 * @returns {string} Self-contained HTML email body.
 */
function buildOtpEmailHtml(otpCode, ttlMinutes) {
    return `
    <div style="background-color:#f4f6f9;padding:32px 16px;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;">
        <table role="presentation" width="100%" style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:8px;overflow:hidden;border:1px solid #e2e5ea;">
            <tr>
                <td style="background-color:#8b0000;padding:20px 28px;">
                    <span style="color:#ffffff;font-size:16px;font-weight:700;letter-spacing:0.5px;">STUDENT INFORMATION SYSTEM</span>
                </td>
            </tr>
            <tr>
                <td style="padding:28px;">
                    <h2 style="margin:0 0 12px;font-size:18px;color:#1a1a1a;">Administrator Verification Code</h2>
                    <p style="margin:0 0 20px;font-size:14px;line-height:1.6;color:#444;">
                        Enter this code to finish signing in to the Admin Portal. It expires in
                        ${ttlMinutes} minutes and can only be used once.
                    </p>
                    <div style="text-align:center;background:#f8f9fb;border:1px solid #e2e5ea;border-radius:6px;padding:18px;margin:0 0 20px;">
                        <span style="font-size:32px;font-weight:700;letter-spacing:0.4em;color:#8b0000;font-family:'Courier New',monospace;">${otpCode}</span>
                    </div>
                    <p style="margin:0;font-size:13px;line-height:1.6;color:#666;">
                        <strong>Didn't request this?</strong> Someone may have your password. Do not
                        share this code with anyone, and contact your system administrator so the
                        account and device can be reviewed.
                    </p>
                </td>
            </tr>
            <tr>
                <td style="padding:16px 28px;background:#f8f9fb;border-top:1px solid #e2e5ea;">
                    <span style="font-size:11px;color:#999;">This is an automated security notification. Please do not reply to this email.</span>
                </td>
            </tr>
        </table>
    </div>`;
}

/**
 * Sends a one-time verification code to an admin account completing the
 * second step of login (see controllers/authController.js). Unlike
 * sendLoginAlert() above, this is on the critical path of the login
 * itself - see this file's @fileoverview for why it resolves to a
 * boolean rather than being fire-and-forget.
 *
 * @param {string} userEmail - Email address of the account signing in; also the recipient.
 * @param {string} otpCode - The 6-digit numeric code to deliver.
 * @param {number} [ttlMinutes=5] - Minutes until the code expires, for display only; must match the caller's actual expiry.
 * @returns {Promise<boolean>} `true` if the email was handed off to the SMTP server successfully, `false` otherwise. Never rejects.
 */
export async function sendOtpEmail(userEmail, otpCode, ttlMinutes = 5) {
    if (!hasMailConfig()) {
        console.warn("[emailService] No mail delivery configured (RESEND_API_KEY or SMTP_EMAIL/SMTP_APP_PASSWORD) - cannot send OTP.");
        return false;
    }

    try {
        await deliver({
            to: userEmail,
            subject: "Your SIS Admin Verification Code",
            html: buildOtpEmailHtml(otpCode, ttlMinutes)
        });

        console.log(`[emailService] OTP sent to ${userEmail}.`);
        return true;
    } catch (err) {
        console.error(`[emailService] Failed to send OTP to ${userEmail}:`, err.message);
        return false;
    }
}
