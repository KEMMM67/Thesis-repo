import { securityConfig } from "../config/securityConfig.js";

// In-memory tracker for active user request timestamps
const activeUsers = {};

// Extracts the user's current behavioral features (Speed and Frequency)
export function getFeatures(user, endpoint) {
    const now = Date.now();

    // Initialize tracking for new users
    if (!activeUsers[user]) {
        activeUsers[user] = {
            requests: [],
            loginAttempts: 0
        };
    }

    const userData = activeUsers[user];

    // Remove obsolete request data that falls outside the defined time window
    userData.requests = userData.requests.filter(time => now - time < securityConfig.windowMs);

    // Calculate the current request velocity, expressed in requests-per-SECOND.
    // (Requests-per-millisecond was mathematically fine but produced tiny
    // fractional numbers - e.g. 0.0033 - that are awkward to reason about.
    // Multiplying by 1000 keeps the exact same relative math while giving
    // the Weighted Endpoint & Velocity Algorithm in core/scorer.js a
    // human-readable input, e.g. "3.3 req/sec".)
    let rate = 0;
    if (userData.requests.length > 1) {
        const timeDiff = now - userData.requests[0];
        rate = timeDiff > 0 ? (userData.requests.length / timeDiff) * 1000 : 0;
    }

    return {
        requestRate: rate,
        loginAttempts: userData.loginAttempts,
        // Surfaced so core/scorer.js can look up this endpoint's
        // Endpoint Sensitivity Weight without securityMiddleware.js
        // needing to change its computeScore() call at all.
        endpoint
    };
}

// Logs incoming requests to update the user's current tracking state
export function updateFeatures(user, endpoint) {
    const now = Date.now();
    
    if (!activeUsers[user]) {
        activeUsers[user] = { requests: [], loginAttempts: 0 };
    }

    // Record the timestamp of the current request
    activeUsers[user].requests.push(now);

    // Increment attempt counter if the user targets the login endpoint
    if (endpoint.includes('login')) {
        activeUsers[user].loginAttempts += 1;
    }
}

// Clears the tracking state upon successful authentication or penalty expiration
export function resetFeatures(user) {
    if (activeUsers[user]) {
        activeUsers[user].loginAttempts = 0;
        activeUsers[user].requests = [];
    }
}