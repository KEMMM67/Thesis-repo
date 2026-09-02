import { securityConfig } from "../config/securityConfig.js";

/** In-memory tracker of per-user request timestamps and login-attempt counts. */
const activeUsers = {};

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

    if (!activeUsers[user]) {
        activeUsers[user] = {
            requests: [],
            loginAttempts: 0
        };
    }

    const userData = activeUsers[user];

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

    if (!activeUsers[user]) {
        activeUsers[user] = { requests: [], loginAttempts: 0 };
    }

    activeUsers[user].requests.push(now);

    if (endpoint.includes('login')) {
        activeUsers[user].loginAttempts += 1;
    }
}

/**
 * Clears a user's tracked request history and login-attempt count,
 * typically invoked on successful authentication so past failures no
 * longer contribute to the anomaly score.
 *
 * @param {string} user - User identifier to reset.
 * @returns {void}
 */
export function resetFeatures(user) {
    if (activeUsers[user]) {
        activeUsers[user].loginAttempts = 0;
        activeUsers[user].requests = [];
    }
}
