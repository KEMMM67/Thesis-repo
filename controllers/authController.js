import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { randomInt, timingSafeEqual } from "crypto";
import prisma from "../config/prisma.js";
import { settleDeviceAttempts } from "../core/monitor.js";
import { settleIpAttempts } from "../core/ipAttempts.js";
import { getClientIdentity, normalizeAccount } from "../middleware/clientIdentity.js";
import { sendLoginAlert, sendOtpEmail } from "../utils/emailService.js";

/**
 * @fileoverview Authentication controllers.
 *
 * Two authentication shapes live here, both mounted behind
 * securityMiddleware in routes/authRoutes.js so a brute-force burst
 * against either is scored and can be THROTTLEd/BLOCKed by WEVA before a
 * single bcrypt.compare() or database call runs (see core/scorer.js,
 * core/mitigation.js):
 *
 *   - Student/faculty accounts: single-step. login() verifies the
 *     password and, on success, immediately issues a JWT via
 *     completeLogin() - unchanged from before two-factor existed.
 *
 *   - Admin accounts: two-step. login() verifies the password but
 *     deliberately withholds the JWT, instead emailing a one-time 6-digit
 *     code (utils/emailService.js) and responding with
 *     { requireOtp: true }. The JWT is only ever minted by verifyOtp(),
 *     once that code is confirmed - see completeLogin() below for why a
 *     correct password alone is treated as "not yet logged in" for this
 *     role.
 */

/** OTP validity window: 5 minutes from issuance, so an intercepted or leaked code stops working quickly. */
const OTP_TTL_MS = 5 * 60 * 1000;

/**
 * Wrong codes allowed per issued OTP before it is cancelled (see
 * verifyOtp()). Without a cap, the only thing between an attacker who
 * already holds an admin's password and the 1,000,000 possible codes was
 * WEVA's rate scoring - which the own-account and device-rotation tricks
 * (core/monitor.js#settleDeviceAttempts, middleware/securityMiddleware.js)
 * could get around. With it, each code can be guessed at most 5 times: a
 * 5 in 1,000,000 chance per code, and every fresh code costs another
 * correct-password login, which WEVA scores as an attempt too.
 */
const MAX_OTP_FAILURES = 5;

/**
 * Wrong-code tally for each admin's pending OTP, keyed by user id:
 * `{ codeId, failures }`, where `codeId` is the code's expiry timestamp -
 * unique per issued code, so a tally left over from an earlier code can
 * never count against a new one.
 *
 * Held in memory like the rest of WEVA's per-request state (one server
 * instance - see core/stateStore.js); a restart forgets tallies, which at
 * worst grants a pending code 5 more guesses before its 5-minute expiry.
 * There is at most one entry per admin, removed when the code is verified,
 * cancelled, expires, or is replaced.
 */
const otpFailures = new Map();

/** Shown once a code has been cancelled; public/admin_login.js displays 401 messages as-is. */
const OTP_CANCELLED_MESSAGE = 'Too many incorrect codes, so this code has been cancelled. Use "Resend code" or sign in again to get a new one.';

/**
 * Generates a cryptographically random 6-digit numeric OTP as a
 * zero-padded string (e.g. "004821"), preserving the full
 * 1,000,000-value keyspace (000000-999999). crypto.randomInt() is
 * CSPRNG-backed (unlike Math.random()), which matters here since a
 * predictable OTP would defeat the entire second factor. Generating in
 * [0, 1000000) and padding, rather than generating directly in
 * [100000, 1000000), matters too: the latter silently excludes every
 * code with a leading zero, discarding 10% of the keyspace and making
 * the code marginally easier to brute-force than its 6 digits suggest.
 *
 * @returns {string} 6-digit numeric OTP.
 */
function generateOtp() {
    return String(randomInt(0, 1000000)).padStart(6, '0');
}

/**
 * Constant-time comparison of the submitted OTP against the stored one,
 * so response timing cannot be used to infer correct digits one at a
 * time - a classic timing side-channel against a naive `===` comparison,
 * which short-circuits at the first mismatched character. The code's
 * fixed length (6) is not itself a secret, so comparing lengths first
 * (required before timingSafeEqual, which throws on a length mismatch
 * rather than returning false) leaks nothing; only the digit comparison
 * itself needs to run in constant time.
 *
 * @param {string} submitted - OTP the client supplied.
 * @param {string} stored - OTP persisted on the user's record.
 * @returns {boolean}
 */
function otpMatches(submitted, stored) {
    const submittedBuf = Buffer.from(String(submitted));
    const storedBuf = Buffer.from(String(stored));
    if (submittedBuf.length !== storedBuf.length) return false;
    return timingSafeEqual(submittedBuf, storedBuf);
}

/**
 * Completes a successful authentication: mints the JWT, persists the
 * backing Session row (see middleware/authMiddleware.js for why a
 * Session row is required, not just a valid signature), settles the WEVA
 * attempts aimed at this account, writes the LOGIN_SUCCESS audit trail,
 * and dispatches the best-effort new-sign-in alert email. Always sends
 * exactly one HTTP response; callers should `return` immediately after
 * calling it.
 *
 * Shared by both authentication paths this controller supports: a
 * non-admin's single-step password login (called directly from login()),
 * and an admin's second step once verifyOtp() confirms the code. Both
 * represent the identical event from the account owner's perspective -
 * "this account is now fully authenticated" - so they deliberately share
 * one implementation rather than writing two slightly-different-looking
 * copies of the same audit trail.
 *
 * Settling WEVA's attempt history is scoped and ordered deliberately:
 *
 *   - Scoped to this account. Only the attempts aimed at `user` are
 *     settled, on both the device and the IP. Settling everything, as
 *     this used to, let anyone with a valid account of their own reset
 *     their guesses at someone else's by logging in between them - see
 *     core/monitor.js#settleDeviceAttempts for the worked example.
 *   - Ordered last. It runs here, at true completion, and nowhere earlier
 *     in the admin flow: settling right after the password step (before
 *     OTP existed, that *was* the completion point) would let an attacker
 *     who holds a valid password clear their OTP guesses on demand.
 *
 * @param {import("@prisma/client").User} user - Authenticated user row.
 * @param {string} ipAddress - Originating IP of the request.
 * @param {string} deviceId - WEVA device identifier (x-device-id header, falling back to IP).
 * @param {import("express").Response} res
 * @returns {Promise<void>}
 */
async function completeLogin(user, ipAddress, deviceId, res) {
    const account = normalizeAccount(user.email);
    settleDeviceAttempts(deviceId, account);
    settleIpAttempts(ipAddress, account);

    const tokenTtlMs = 60 * 60 * 1000; // must match the JWT expiresIn below
    const token = jwt.sign(
        { email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );

    // upsert guards against the vanishingly unlikely case of an
    // identical JWT (same payload, same issued-at second) without ever
    // failing a login because of it.
    try {
        await prisma.session.upsert({
            where: { sessionToken: token },
            update: { userId: user.id, expiresAt: new Date(Date.now() + tokenTtlMs) },
            create: { userId: user.id, sessionToken: token, expiresAt: new Date(Date.now() + tokenTtlMs) }
        });
    } catch (sessionErr) {
        console.error("Session creation failed on login:", sessionErr.message);
        res.status(500).json({ success: false, message: "Could not establish a secure session. Please try again." });
        return;
    }

    try {
        await Promise.all([
            prisma.loginAttempt.create({
                data: { userEmail: user.email, userId: user.id, ipAddress, status: 'SUCCESS' }
            }),
            prisma.behaviorLog.create({
                data: { userEmail: user.email, userId: user.id, eventType: 'LOGIN_SUCCESS', description: 'User logged in successfully.' }
            })
        ]);
    } catch (logErr) {
        console.error("Audit log write failed on successful login:", logErr.message);
    }

    // Not awaited: sendLoginAlert() already catches every failure
    // internally and always resolves (see utils/emailService.js), and
    // the response below must not wait on a round trip to an external
    // SMTP server.
    sendLoginAlert(user.email, ipAddress);

    res.json({ success: true, message: "Login successful!", role: user.role, token });
}

/**
 * Records a failed authentication attempt against the shared LOGIN_FAILED
 * audit trail. Used for both a wrong password (login()) and a
 * wrong/expired/missing OTP (verifyOtp()) - both are, from the audit
 * trail's perspective, the same kind of event ("this login attempt did
 * not succeed"), so they intentionally share one eventType; the
 * human-readable `description` is what tells them apart in the admin
 * dashboard's Security Logs table.
 *
 * @param {string} email - Email address as submitted by the client (may not correspond to a real account).
 * @param {import("@prisma/client").User|null|undefined} user - Resolved user row, if one exists.
 * @param {string} ipAddress - Originating IP of the request.
 * @param {string} description - Human-readable reason, shown in the dashboard.
 * @returns {Promise<void>}
 */
async function recordFailedAttempt(email, user, ipAddress, description) {
    try {
        await Promise.all([
            prisma.loginAttempt.create({
                data: { userEmail: email, userId: user?.id ?? null, ipAddress, status: 'FAILED' }
            }),
            prisma.behaviorLog.create({
                data: { userEmail: email, userId: user?.id ?? null, eventType: 'LOGIN_FAILED', description }
            })
        ]);
    } catch (logErr) {
        console.error("Audit log write failed on failed login:", logErr.message);
    }
}

/**
 * Generates and dispatches an OTP for an admin whose password has just
 * been verified, and responds with the { requireOtp: true } shape the
 * frontend uses to switch from the credentials form to the OTP form (see
 * public/admin_login.js).
 *
 * Deliberately does not write a LoginAttempt/LOGIN_SUCCESS row: those
 * represent a *resolved* login (see completeLogin() and
 * recordFailedAttempt() above), and this account's login is still
 * pending its second factor. It gets its own OTP_REQUESTED BehaviorLog
 * entry instead, so the audit trail still shows the password step
 * happened without misrepresenting it as a completed login.
 *
 * @param {import("@prisma/client").User} user - Admin whose password just matched.
 * @param {import("express").Response} res
 * @returns {Promise<void>}
 */
async function beginOtpChallenge(user, res) {
    const otpCode = generateOtp();
    const otpExpiresAt = new Date(Date.now() + OTP_TTL_MS);
    otpFailures.delete(user.id);

    try {
        await prisma.user.update({
            where: { id: user.id },
            data: { otpCode, otpExpiresAt }
        });
    } catch (err) {
        console.error("Failed to persist OTP:", err.message);
        res.status(500).json({ success: false, message: "Could not start verification. Please try again." });
        return;
    }

    try {
        await prisma.behaviorLog.create({
            data: {
                userEmail: user.email,
                userId: user.id,
                eventType: 'OTP_REQUESTED',
                description: 'Password verified; OTP dispatched to admin email pending second-factor verification.'
            }
        });
    } catch (logErr) {
        console.error("Audit log write failed on OTP dispatch:", logErr.message);
    }

    // Awaited (unlike sendLoginAlert above): for an admin, this email is
    // the only channel carrying the code needed to finish logging in, so
    // a silent delivery failure must not be reported to the client as
    // success - see utils/emailService.js's @fileoverview.
    const sent = await sendOtpEmail(user.email, otpCode, OTP_TTL_MS / 60000);
    if (!sent) {
        res.status(500).json({ success: false, message: "Could not send verification code. Please try again." });
        return;
    }

    res.json({ success: true, requireOtp: true, email: user.email, message: "OTP sent to email" });
}

/**
 * @route POST /api/login
 * @access Public
 * @description Authenticates a user by email and password. Non-admin
 * accounts are logged in immediately on a password match (completeLogin()
 * below). Admin accounts are not: a correct password only advances them
 * to a mandatory OTP challenge (beginOtpChallenge()) - no JWT is issued
 * until POST /api/verify-otp confirms the code.
 *
 * Mounted behind securityMiddleware in routes/authRoutes.js: a
 * brute-force burst is scored and can be BLOCKed/THROTTLEd by WEVA
 * before a single request reaches the bcrypt.compare() or database calls
 * below (see core/scorer.js, core/mitigation.js).
 *
 * @param {import("express").Request} req
 * @param {import("express").Response} res
 * @returns {Promise<void>}
 */
export async function login(req, res) {
    const { email, password } = req.body;
    // Same identity derivation securityMiddleware scored this request under,
    // so completeLogin() clears exactly those keys.
    const { ip: ipAddress, deviceKey: deviceId } = getClientIdentity(req);

    try {
        const user = await prisma.user.findUnique({ where: { email } });
        const passwordMatches = user ? await bcrypt.compare(password, user.passwordHash) : false;

        if (passwordMatches) {
            if (user.role === 'admin') {
                await beginOtpChallenge(user, res);
            } else {
                await completeLogin(user, ipAddress, deviceId, res);
            }
        } else {
            await recordFailedAttempt(email, user, ipAddress, 'Invalid password attempted.');
            res.status(401).json({ success: false, message: "Invalid email or password." });
        }
    } catch (err) {
        console.error("Database query error:", err);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
}

/**
 * @route POST /api/verify-otp
 * @access Public
 * @description Confirms the second factor of an admin login and, only on
 * success, issues the JWT that POST /api/login withheld. No JWT or
 * Session row exists prior to this succeeding, so - like POST /api/login
 * - this route carries no Authorization header and cannot be gated by
 * authMiddleware; it is public by necessity, which is exactly why it (like
 * POST /api/login) is mounted behind securityMiddleware in
 * routes/authRoutes.js instead. A 6-digit code is a far smaller search
 * space than a password, so without WEVA scoring this endpoint too, it
 * would be the weakest link in the entire authentication chain.
 *
 * Every rejection path below returns 401, and none of them reveal whether
 * `email` belongs to a real account: an unknown email and a real admin
 * account with no pending OTP both fall into the generic "Invalid or
 * expired OTP" branch, so this endpoint cannot be used to enumerate admin
 * email addresses. Only an account with a code pending - which takes its
 * correct password to get - sees the more specific messages below.
 *
 * Each code allows MAX_OTP_FAILURES (5) wrong guesses; the 5th cancels it,
 * so the admin must request a new one. That caps guessing at 5 per code on
 * its own, independent of WEVA's rate scoring. And a code is consumed with
 * a conditional update, so it can be used exactly once even when two
 * requests carry it at the same time.
 *
 * @param {import("express").Request} req
 * @param {import("express").Response} res
 * @returns {Promise<void>}
 */
export async function verifyOtp(req, res) {
    const { email, otp } = req.body;
    const { ip: ipAddress, deviceKey: deviceId } = getClientIdentity(req);

    if (!email || !otp) {
        return res.status(400).json({ success: false, message: "Email and OTP are required." });
    }

    try {
        const user = await prisma.user.findUnique({ where: { email } });

        if (!user || !user.otpCode) {
            await recordFailedAttempt(email, user, ipAddress, 'OTP verification attempted with no pending code for this account.');
            return res.status(401).json({ success: false, message: "Invalid or expired OTP." });
        }

        if (user.otpExpiresAt <= new Date()) {
            otpFailures.delete(user.id);
            await prisma.user.update({ where: { id: user.id }, data: { otpCode: null, otpExpiresAt: null } });
            await recordFailedAttempt(email, user, ipAddress, 'OTP expired before verification.');
            return res.status(401).json({ success: false, message: "OTP has expired. Please log in again to request a new code." });
        }

        // Read, check and update the wrong-code tally with no `await` in
        // between, so simultaneous guesses are counted one after another:
        // a burst of 20 parallel guesses gets 5 comparisons against the
        // code, not 20. A cancelled code's tally is kept (not deleted) until
        // a new code replaces it, so a guess that read the code just before
        // the cancellation reached the database is still refused here.
        const codeId = user.otpExpiresAt.getTime();
        const tally = otpFailures.get(user.id);
        const priorFailures = tally?.codeId === codeId ? tally.failures : 0;

        if (priorFailures >= MAX_OTP_FAILURES) {
            await recordFailedAttempt(email, user, ipAddress, 'OTP guess refused: the code was already cancelled after too many incorrect attempts.');
            return res.status(401).json({ success: false, message: OTP_CANCELLED_MESSAGE });
        }

        if (!otpMatches(otp, user.otpCode)) {
            const failures = priorFailures + 1;
            otpFailures.set(user.id, { codeId, failures });

            if (failures >= MAX_OTP_FAILURES) {
                await prisma.user.update({ where: { id: user.id }, data: { otpCode: null, otpExpiresAt: null } });
                await recordFailedAttempt(email, user, ipAddress, `OTP cancelled after ${MAX_OTP_FAILURES} incorrect attempts.`);
                return res.status(401).json({ success: false, message: OTP_CANCELLED_MESSAGE });
            }

            await recordFailedAttempt(email, user, ipAddress, 'Invalid OTP attempted.');
            const left = MAX_OTP_FAILURES - failures;
            return res.status(401).json({ success: false, message: `Invalid OTP. ${left} ${left === 1 ? 'attempt' : 'attempts'} left before this code is cancelled.` });
        }

        // Single use, even under concurrency: the code is consumed only if it
        // is still the one this request read. Two simultaneous requests with
        // the same correct code both pass the comparison above, but only the
        // first matches here - the second finds the code already gone.
        const consumed = await prisma.user.updateMany({
            where: { id: user.id, otpCode: user.otpCode },
            data: { otpCode: null, otpExpiresAt: null }
        });
        if (consumed.count !== 1) {
            await recordFailedAttempt(email, user, ipAddress, 'OTP already used by a simultaneous request.');
            return res.status(401).json({ success: false, message: "Invalid or expired OTP." });
        }

        otpFailures.delete(user.id);
        await completeLogin(user, ipAddress, deviceId, res);
    } catch (err) {
        console.error("OTP verification error:", err);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
}
