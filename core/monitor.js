import { securityConfig } from "../config/securityConfig.js";
import { MemoryStateStore } from "./stateStore.js";

/**
 * Backing store for per-user/device request timestamps and login-attempt
 * counts. Previously a bare module-level object (`activeUsers`) that grew
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
 * Derives a user's current behavioral features - request velocity and
 * outstanding login attempts - for input to core/scorer.js.
 *
 * Velocity is expressed in requests/second rather than requests/ms so that
 * the Weighted Endpoint & Velocity Algorithm operates on human-readable
 * values (e.g. "3.3 req/sec") without altering the underlying ratio.
 *
 * @param {string} user - User identifier (or device identifier for pre-auth requests).
 * @param {string} endpoint - Normalized endpoint path of the current request.
 * @returns {{requestRate: number, loginAttempts: number, endpoint: string}}
 */
export function getFeatures(user, endpoint) {
    const now = Date.now();
    const userData = store.getOrCreate(user, () => ({ requests: [], loginAttempts: 0 }));

    // Drop timestamps outside the scoring window so velocity reflects
    // recent behavior only.
    userData.requests = userData.requests.filter(time => now - time < securityConfig.windowMs);

    let rate = 0;
    if (userData.requests.length > 1) {
        const timeDiff = now - userData.requests[0];
        rate = timeDiff > 0 ? (userData.requests.length / timeDiff) * 1000 : 0;
    }

    return {
        requestRate: rate,
        loginAttempts: userData.loginAttempts,
        endpoint
    };
}

/**
 * Records the current request against the user's tracking state, updating
 * the request history used for velocity calculation and, for login
 * endpoints, the outstanding-attempt counter consumed by the scorer's fail
 * rate factor.
 *
 * @param {string} user - User identifier (or device identifier for pre-auth requests).
 * @param {string} endpoint - Endpoint path of the current request.
 * @returns {void}
 */
export function updateFeatures(user, endpoint) {
    const now = Date.now();
    const userData = store.getOrCreate(user, () => ({ requests: [], loginAttempts: 0 }));

    userData.requests.push(now);

    if (AUTH_ATTEMPT_ENDPOINT_MARKERS.some(marker => endpoint.includes(marker))) {
        userData.loginAttempts += 1;
    }
}

/**
 * Clears a user's tracked request history and login-attempt count.
 *
 * For a non-admin's single-step login this fires as soon as the password
 * matches, same as before two-factor existed. For an admin's two-step
 * login it must NOT fire until the OTP is verified (see
 * controllers/authController.js's completeLogin()) - resetting it after
 * the password step alone would let an attacker who already holds a
 * valid password wipe this device's entire attempt history on demand
 * simply by re-submitting POST /api/login, then take one fresh,
 * unamplified guess at the OTP before resetting again. Only clearing the
 * slate once the full chain succeeds means every OTP guess in between
 * keeps compounding the same fail-rate factor a run of wrong passwords
 * would.
 *
 * Only resets an entry that already exists, matching this function's
 * original behavior from before MemoryStateStore existed - a device with
 * no tracked state yet has nothing to clear.
 *
 * @param {string} user - User identifier to reset.
 * @returns {void}
 */
export function resetFeatures(user) {
    if (store.has(user)) {
        store.set(user, { requests: [], loginAttempts: 0 });
    }
}
