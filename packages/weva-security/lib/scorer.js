/**
 * @fileoverview The WEVA formula (Weighted Endpoint & Velocity Algorithm),
 * ported from the thesis build's core/scorer.js with the same factors and the
 * same defaults. test/scorer.js checks the two against each other.
 *
 *     score = velocityIncrement x endpointWeight x failRateFactor x velocityPointScale
 *
 * The factors are multiplied, not added, because risk compounds: speed on a
 * harmless route is mildly interesting, the same speed on a destructive route
 * is serious, and more so from a client that keeps failing logins. A first
 * request has no velocity and no failures, so it scores 0 without a special
 * case.
 */

/**
 * The thesis build's tuning. `endpointWeights` starts empty: the host
 * application lists its own routes (see index.js).
 */
export const DEFAULT_SCORING = Object.freeze({
    minVelocityFloor: 2,      // velocity assumed while failed logins are outstanding
    failRateIncrement: 0.5,   // added to the fail-rate factor per outstanding failed login
    velocityPointScale: 5,    // maps the product onto the 0-100 scale the thresholds use
    defaultEndpointWeight: 1,
    endpointWeights: Object.freeze({})
});

/**
 * Factor 1: how far the client's request rate is above its own learned
 * baseline. Only a rise counts; slowing down is never penalized.
 *
 * While the client has failed logins outstanding, the increment is at least
 * `minVelocityFloor`. Without the floor a patient guesser, one attempt every
 * few seconds, would have a velocity of 0, and anything times 0 is 0.
 *
 * @param {{requestRate: number, loginAttempts: number}} current
 * @param {{requestRate: number}} baseline
 * @param {number} minVelocityFloor
 * @returns {number}
 */
function getVelocityIncrement(current, baseline, minVelocityFloor) {
    let increment = Math.max(0, (current.requestRate || 0) - (baseline.requestRate || 0));
    if ((current.loginAttempts || 0) > 0) increment = Math.max(increment, minVelocityFloor);
    return increment;
}

/**
 * Factor 2: the route's blast radius - 1 routine, 2 authentication,
 * 3 one-record writes, 4 whole-database operations.
 *
 * @param {string} endpoint - Route pattern the request matched, e.g. "/api/students/:id".
 * @param {Record<string, number>} endpointWeights
 * @param {number} defaultEndpointWeight
 * @returns {number}
 */
function getEndpointWeight(endpoint, endpointWeights, defaultEndpointWeight) {
    return Object.hasOwn(endpointWeights, endpoint) ? endpointWeights[endpoint] : defaultEndpointWeight;
}

/**
 * Factor 3: 1 + failRateIncrement per failed login not yet settled by a
 * successful one. Exactly 1 when there are none, so normal traffic is never
 * distorted.
 *
 * @param {number} loginAttempts
 * @param {number} failRateIncrement
 * @returns {number}
 */
function getFailRateFactor(loginAttempts, failRateIncrement) {
    return 1 + Math.max(0, loginAttempts || 0) * failRateIncrement;
}

/**
 * Scores one request, 0-100. Worked examples with the defaults, a login route
 * weighted 2 and the default thresholds (LOG 25, THROTTLE 60, BLOCK 85):
 *
 *   1st login attempt, nothing outstanding    0 x 2 x 1   x 5 =  0   ALLOW
 *   5th attempt, 4 failures outstanding       2 x 2 x 3   x 5 = 60   THROTTLE
 *   8th attempt, 7 failures outstanding       2 x 2 x 4.5 x 5 = 90   BLOCK
 *   +3 req/s above baseline on a 3x route     3 x 3 x 1   x 5 = 45   LOG
 *
 * Every factor is returned with the score, so each verdict can be audited.
 *
 * @param {{requestRate: number, loginAttempts: number, endpoint: string}} current
 * @param {{requestRate: number}} baseline
 * @param {typeof DEFAULT_SCORING} [config]
 * @returns {{score: number, breakdown: {velocityIncrement: number, endpointWeight: number, failRateFactor: number, scale: number, formula: string}}}
 */
export function computeScore(current, baseline, config = DEFAULT_SCORING) {
    const velocityIncrement = getVelocityIncrement(current, baseline, config.minVelocityFloor);
    const endpointWeight = getEndpointWeight(current.endpoint, config.endpointWeights, config.defaultEndpointWeight);
    const failRateFactor = getFailRateFactor(current.loginAttempts, config.failRateIncrement);

    const raw = velocityIncrement * endpointWeight * failRateFactor * config.velocityPointScale;
    const score = Math.min(Math.round(Math.max(raw, 0)), 100);

    const v = round2(velocityIncrement);
    const f = round2(failRateFactor);
    return {
        score,
        breakdown: {
            velocityIncrement: v,
            endpointWeight,
            failRateFactor: f,
            scale: config.velocityPointScale,
            formula: `${v} x ${endpointWeight} x ${f} x ${config.velocityPointScale} = ${score}`
        }
    };
}

/**
 * @param {number} n
 * @returns {number} `n` rounded to 2 decimals, for the formula string.
 */
function round2(n) {
    return Math.round(n * 100) / 100;
}
