import { securityConfig } from "../config/securityConfig.js";
import { MemoryStateStore } from "./stateStore.js";

/**
 * Backing store for per-identity request timestamps and login-attempt
 * ledgers. The key is whichever identity middleware/securityMiddleware.js is
 * scoring: a device ID, an IP (for clients that send no device ID), or an
 * account key ("user:<id>", see middleware/clientIdentity.js#accountKey).
 * Previously a bare module-level object (`activeUsers`) that grew
 * by one permanent entry for every device/IP ever seen, for the lifetime
 * of the process, with nothing to remove an entry once that device went
 * away - a genuine unbounded-memory-growth bug, not just a style issue.
 * MemoryStateStore (core/stateStore.js) fixes that by evicting an entry
 * once it has sat idle for 30 minutes, while preserving the exact
 * "get-or-create" access pattern this module already relied on. It is
 * also the seam that lets this state later live in Redis instead
 * (a RedisStateStore implementing the same get/set contract), so WEVA's
 * behavioral tracking stays correct if this server is ever scaled to more
 * than one process - see core/mitigation.js, which already made that
 * exact argument for why ipTracking is persisted in the database rather
 * than kept in memory.
 */
const store = new MemoryStateStore();

/**
 * Endpoint path substrings that count toward `loginAttempts`. This
 * originally matched only "login", back when a single POST /api/login
 * was the entire credential-verification chain. Admin accounts now
 * authenticate in two steps - password at /api/login, then a one-time
 * code at /api/verify-otp (see controllers/authController.js) - and both
 * steps must contribute to the same counter, or an attacker who already
 * holds a valid password could brute-force the 6-digit OTP with
 * complete impunity: guesses against /api/verify-otp would never raise
 * loginAttempts, so getVelocityIncrement()'s minimum velocity floor and
 * getFailRateFactor() in core/scorer.js would never engage for them,
 * regardless of how many were sent. Treating both endpoints as one
 * "unresolved authentication attempt" stream closes that gap and, since
 * they share the same counter, extends WEVA's already-proven
 * password-brute-force thresholds (see the worked examples in
 * core/scorer.js#computeScore) to OTP-guessing for free.
 */
const AUTH_ATTEMPT_ENDPOINT_MARKERS = ['login', 'verify-otp'];

/**
 * A new identity's state.
 *
 *   - requests: timestamps inside the scoring window, for velocity.
 *   - attemptsByAccount: the ledger of authentication attempts not yet
 *     settled by a successful login, keyed by the account each one was
 *     aimed at (middleware/clientIdentity.js#readTargetAccount). Recording
 *     the target, instead of keeping one bare counter, is what lets a
 *     successful login settle only its own account's attempts - see
 *     settleDeviceAttempts() below for the attack a bare counter allowed.
 *
 * @returns {{requests: number[], attemptsByAccount: Map<string, number>}}
 */
function freshState() {
    return { requests: [], attemptsByAccount: new Map() };
}

/**
 * @param {{attemptsByAccount: Map<string, number>}} state
 * @returns {number} Every attempt still on the ledger, whichever account it targeted.
 */
function outstandingAttempts(state) {
    let total = 0;
    for (const count of state.attemptsByAccount.values()) total += count;
    return total;
}

/**
 * Derives an identity's current behavioral features - request velocity and
 * outstanding login attempts - for input to core/scorer.js.
 *
 * Velocity is expressed in requests/second rather than requests/ms so that
 * the Weighted Endpoint & Velocity Algorithm operates on human-readable
 * values (e.g. "3.3 req/sec") without altering the underlying ratio.
 *
 * `loginAttempts` counts every unsettled attempt on the ledger, across all
 * target accounts: a device that has failed against three different
 * accounts is exactly as suspicious as one that failed three times against
 * one (the former is password spraying).
 *
 * @param {string} user - Identity key (device ID, IP, or account key).
 * @param {string} endpoint - Endpoint of the current request.
 * @returns {{requestRate: number, loginAttempts: number, endpoint: string}}
 */
export function getFeatures(user, endpoint) {
    const now = Date.now();
    const userData = store.getOrCreate(user, freshState);

    // Drop timestamps outside the scoring window so velocity reflects
    // recent behavior only.
    userData.requests = userData.requests.filter(time => now - time < securityConfig.windowMs);

    // Date.now() only resolves to whole milliseconds, so several prior
    // requests can share the current millisecond exactly - requests arriving
    // together over parallel connections can do this. The previous
    // `timeDiff > 0 ? ... : 0` guard then reported a rate of 0, scoring the
    // fastest possible burst as no velocity at all. Treating that span as
    // 1 ms instead makes the rate a lower bound rather than a false zero:
    // n prior requests inside one millisecond is at least n x 1000 req/s.
    // Worked example: a burst's 3rd request with 2 prior requests in the same
    // millisecond -> 2 / 1 ms = 2000 req/s, and against a fresh device's
    // baseline of 0 that scores min(100, 2000 x 2 x 2 x 5) = 100 -> BLOCK,
    // where the old guard gave it only the floor score, 2 x 2 x 2 x 5 = 40
    // (LOG).
    let rate = 0;
    if (userData.requests.length > 1) {
        const timeDiff = Math.max(now - userData.requests[0], 1);
        rate = (userData.requests.length / timeDiff) * 1000;
    }

    return {
        requestRate: rate,
        loginAttempts: outstandingAttempts(userData),
        endpoint
    };
}

/**
 * Records the current request against the identity's tracking state: its
 * timestamp for velocity and, for an authentication endpoint, one more
 * attempt on the ledger under the account it targeted.
 *
 * @param {string} user - Identity key (device ID, IP, or account key).
 * @param {string} endpoint - Endpoint of the current request.
 * @param {string} [account=""] - Normalized target account of a login/OTP attempt (middleware/clientIdentity.js#readTargetAccount); ignored for other endpoints.
 * @returns {void}
 */
export function updateFeatures(user, endpoint, account = '') {
    const now = Date.now();
    const userData = store.getOrCreate(user, freshState);

    userData.requests.push(now);

    if (isAuthAttemptEndpoint(endpoint)) {
        userData.attemptsByAccount.set(account, (userData.attemptsByAccount.get(account) || 0) + 1);
    }
}

/**
 * Whether a request to `endpoint` is a credential-verification attempt (a
 * password at /api/login or an OTP at /api/verify-otp - see
 * AUTH_ATTEMPT_ENDPOINT_MARKERS above). Shared with
 * middleware/securityMiddleware.js, which also counts these per IP
 * (core/ipAttempts.js).
 *
 * @param {string} endpoint
 * @returns {boolean}
 */
export function isAuthAttemptEndpoint(endpoint) {
    return AUTH_ATTEMPT_ENDPOINT_MARKERS.some(marker => endpoint.includes(marker));
}

/**
 * Settles a device's history after a successful login to `account`: the
 * attempts it made against that account come off the ledger, and its
 * velocity window starts over. Attempts it made against any other account
 * stay exactly where they are.
 *
 * Why only that account. This used to reset the device completely -
 * velocity and every attempt - on any successful login. That let anyone
 * with a valid account of their own brute-force someone else's: three
 * guesses at the victim, one login to their own account (which wiped the
 * three guesses), repeat. Against the real middleware that got 300 of 300
 * guesses through to the password check, where the same attack without the
 * interleaved logins got 4. Settling per account closes that loop.
 *
 * Worked example - one device, a student who owns account M guessing at V:
 *
 *   V, V, V (wrong)  -> ledger { V: 3 }
 *   M (correct)      -> the M attempt comes off; ledger stays { V: 3 }
 *   next guess at V  -> 3 attempts outstanding:
 *                       2 x 2 x (1 + 3 x 0.5) x 5 = 50  (LOG)
 *   the one after    -> 2 x 2 x 3 x 5 = 60             (THROTTLE)
 *
 * - the same ladder as if the M login had never happened (core/scorer.js's
 * worked examples: THROTTLE on the 5th attempt at V, BLOCK on the 8th).
 *
 * A legitimate user is unaffected: mistyping their own password twice and
 * then getting it right puts all three attempts under their own account, so
 * the success settles all three - exactly the clean slate the full reset
 * used to give.
 *
 * Why velocity still starts over. The velocity window is not a record of
 * failures; it measures how fast the device is acting now, and the
 * login exchange that just finished is not part of whatever the user does
 * next. Keeping it would let the one or two login requests dilute the rate
 * of an admin's next actions (the Simulate Attack demo, a burst of edits)
 * for up to 30 seconds. Clearing it gives an attacker nothing: guessing is
 * escalated by the ledger above, and a burst is caught on its 3rd request
 * with no history at all.
 *
 * Ordering matters for admins: this runs only once the OTP step succeeds
 * (controllers/authController.js#completeLogin), never after the password
 * step alone. Settling there would let an attacker who already holds a valid
 * password clear the device's OTP guesses on demand by re-submitting the
 * password, then take a fresh, unamplified guess at the code.
 *
 * Only settles an identity that is already tracked - a device with no
 * state has nothing to settle.
 *
 * @param {string} deviceKey - Device key the successful login came from (middleware/clientIdentity.js#getClientIdentity).
 * @param {string} account - Normalized account that just logged in (middleware/clientIdentity.js#normalizeAccount).
 * @returns {void}
 */
export function settleDeviceAttempts(deviceKey, account) {
    if (!store.has(deviceKey)) return;
    const state = store.getOrCreate(deviceKey, freshState);
    state.requests = [];
    state.attemptsByAccount.delete(account);
}
