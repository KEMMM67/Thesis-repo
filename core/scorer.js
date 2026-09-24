/**
 * @fileoverview Weighted Endpoint & Velocity Algorithm (WEVA).
 *
 * Computes an anomaly score as a single multiplicative formula:
 *
 *     score = velocityIncrement * endpointWeight * failRateFactor * velocityPointScale
 *
 * The three factors are multiplied rather than summed because risk is
 * compounding, not additive: an elevated request rate is only mildly
 * interesting on a harmless endpoint, but the same rate against a
 * destructive endpoint (e.g. deleting a record, or a database restore) is
 * far more significant, and more significant still if the device also has
 * a trail of unresolved login attempts. Multiplication lets each factor
 * amplify the others instead of merely stacking.
 *
 *   score = velocityIncrement  x  endpointWeight  x  failRateFactor
 *           (deviation from       (blast radius of    (recent unresolved
 *            the device's own      the endpoint          login attempts)
 *            baseline velocity)    being hit)
 *
 * This also removes the need for a special-cased "grace period" on a
 * user's first request: with no prior timestamp (requestRate = 0) and no
 * prior login attempts, velocityIncrement is 0, and since the factors are
 * multiplied, the whole score resolves to 0 without a dedicated branch.
 *
 * Every tunable in this formula - the endpoint weight table, the minimum
 * velocity floor, the fail-rate amplification per attempt, and the
 * points-per-unit scale - is supplied via a `config` object (see
 * `defaultWevaConfig` below) instead of being hardcoded, so this algorithm
 * can be reused against a different application's routes/tuning without
 * editing this file. Every call site in this app passes no config at all
 * and gets `defaultWevaConfig`, which reproduces the exact values this
 * file hardcoded before configuration injection existed - see
 * core/scorer.test.js for the worked examples that pin that default's
 * behavior.
 */

// ---------------------------------------------------------------------
// FACTOR 1: REQUEST VELOCITY INCREMENT
// ---------------------------------------------------------------------
/**
 * Computes how far above a device's own learned baseline its current
 * request velocity is. Only positive deviations count - a device slowing
 * down relative to its history is never penalized.
 *
 * `minVelocityFloor` is the minimum velocity term applied whenever a
 * device has outstanding, unresolved login attempts. A purely
 * multiplicative formula has one sharp edge: multiplying by a velocity of
 * zero always yields a score of zero, regardless of how suspicious the
 * other factors are. Without this floor, a slow, deliberately-paced
 * brute-force attempt (e.g. one attempt every few seconds, within
 * "normal" velocity) could evade detection indefinitely.
 *
 * This floor intentionally does not apply to a slow attacker probing a
 * non-login endpoint with no attempt trail (e.g. one DELETE request every
 * 40 seconds). Detecting purely volume-based, low-and-slow abuse of
 * arbitrary endpoints is out of scope for a rate-based algorithm and would
 * require a complementary long-window request counter as future work.
 *
 * @param {{requestRate: number, loginAttempts: number}} currentFeatures - Current request features.
 * @param {{requestRate: number}} baselineFeatures - Device's learned baseline (core/profiler.js).
 * @param {number} minVelocityFloor - Minimum increment applied when login attempts are outstanding (config.minVelocityFloor).
 * @returns {number} Velocity increment, floored to `minVelocityFloor` when login attempts are outstanding.
 */
function getVelocityIncrement(currentFeatures, baselineFeatures, minVelocityFloor) {
    const currentRate = currentFeatures.requestRate || 0;
    const baselineRate = baselineFeatures.requestRate || 0;

    let increment = currentRate - baselineRate;
    if (increment < 0) increment = 0;

    if ((currentFeatures.loginAttempts || 0) > 0) {
        increment = Math.max(increment, minVelocityFloor);
    }

    return increment;
}

// ---------------------------------------------------------------------
// FACTOR 2: ENDPOINT SENSITIVITY WEIGHT
// ---------------------------------------------------------------------
/**
 * Collapses dynamic path segments to their route pattern so an
 * `endpointWeights` table needs one entry per route rather than per
 * concrete ID. Handles numeric database IDs, student ID codes in both of
 * this app's formats (e.g. "A23-00001" and the bulk-seeded "CC25-000001"),
 * and subject codes (e.g. "SE301"). Pure path-shape logic with nothing
 * app-specific in it, so - unlike `endpointWeights` itself - this needs no
 * config parameter.
 *
 * This is now only the fallback. middleware/securityMiddleware.js hands the
 * scorer the Express route pattern that matched the request (e.g.
 * "/api/students/:id") whenever there is one, which contains no ID to
 * guess at, so this regex only matters when WEVA is mounted app-wide with
 * app.use(), where no route has matched yet. Guessing IDs by their shape is
 * what used to go wrong: the regex recognised only one-letter IDs, so a
 * DELETE of any of the 15,000 bulk-seeded students ("CC25-000001") fell
 * through to the default weight - 1x instead of 3x.
 *
 * @param {string} rawPath - Raw request path.
 * @returns {string} Path with dynamic ID segments replaced by ":id".
 */
function normalizePath(rawPath) {
    return rawPath.replace(
        /\/([0-9]+|[A-Za-z]{1,4}\d{2}-\d{4,6}|[A-Za-z]{2,4}\d{3})(?=\/|$)/g,
        "/:id"
    );
}

/**
 * @param {string} endpoint - Request endpoint path.
 * @param {Record<string, number>} endpointWeights - Map of normalized route to sensitivity weight (config.endpointWeights).
 * @param {number} defaultEndpointWeight - Weight used when `endpoint` matches no entry in `endpointWeights` (config.defaultEndpointWeight).
 * @returns {number} Endpoint sensitivity weight.
 */
function getEndpointWeight(endpoint, endpointWeights, defaultEndpointWeight) {
    if (!endpoint) return defaultEndpointWeight;
    const normalized = normalizePath(endpoint);
    return endpointWeights[normalized] ?? endpointWeights[endpoint] ?? defaultEndpointWeight;
}

// ---------------------------------------------------------------------
// FACTOR 3: ERROR / FAIL RATE MULTIPLIER
// ---------------------------------------------------------------------
/**
 * `failRateIncrement` is the amplification applied per outstanding login
 * attempt. core/monitor.js tracks `loginAttempts` as the device's
 * authentication attempts that no successful login has settled yet - a
 * success settles only the attempts aimed at its own account (see
 * core/monitor.js#settleDeviceAttempts), so logging into one account never
 * erases failures against another. That makes it a proxy for "this device
 * keeps failing / retrying." When no attempts are outstanding the factor
 * resolves to exactly 1 (a no-op), so it only ever amplifies the score and
 * never distorts normal traffic.
 *
 *   failRateFactor = 1 + (loginAttempts * failRateIncrement)
 *
 * @param {number} loginAttempts - Outstanding unresolved login attempts for the device.
 * @param {number} failRateIncrement - Amplification per outstanding attempt (config.failRateIncrement).
 * @returns {number} Fail rate multiplier, >= 1.
 */
function getFailRateFactor(loginAttempts, failRateIncrement) {
    const attempts = Math.max(0, loginAttempts || 0);
    return 1 + (attempts * failRateIncrement);
}

// ---------------------------------------------------------------------
// DEFAULT CONFIGURATION
// ---------------------------------------------------------------------
/**
 * Default tuning for computeScore(), used whenever a caller omits the
 * `config` argument - which is how every call site in this app invokes it
 * today (see middleware/securityMiddleware.js). These are the exact
 * values this file hardcoded before configuration injection existed, so
 * nothing about this app's behavior changes by default; a different host
 * application plugging WEVA into its own routes supplies its own
 * `endpointWeights` (and, if it needs to, its own floor/increment/scale)
 * instead of editing this file.
 *
 * Endpoint weight tiers, unchanged from before this file became
 * configurable:
 *
 *   1x - routine, read-mostly, low blast-radius endpoints (also the
 *        default for any endpoint with no explicit entry)
 *   2x - authentication and other moderately sensitive endpoints
 *   3x - endpoints that create or mutate a single persistent record
 *   4x - destructive or infrastructure-wide endpoints
 *
 * Keys are Express route patterns. middleware/securityMiddleware.js scores
 * each request under the pattern that matched it ("/api/students/:id"),
 * and normalizePath() collapses concrete IDs to ":id" when no pattern is
 * available, so every request resolves to its route's dictionary entry
 * rather than the default weight. PUT and DELETE
 * on the same resource path (e.g. "/api/students/:id") share the same 3x
 * tier: both mutate a single record, and distinguishing them would
 * require threading the HTTP method through
 * middleware/securityMiddleware.js into this module, which is
 * intentionally left unchanged. The 4x tier is reserved for actions with
 * system-wide blast radius (database backup/restore), keeping the rule
 * simple to defend: weight scales with blast radius, one record versus
 * the whole database.
 *
 * Frozen (including the nested `endpointWeights` map) so a caller can
 * safely omit `config` without risking some other part of the app
 * mutating everyone else's default out from under them - a config object
 * meant to be shared should not be silently editable in place.
 */
export const defaultWevaConfig = {
    minVelocityFloor: 2,
    failRateIncrement: 0.5,

    // Converts the raw (velocity x weight x failRate) product into points
    // on the system's 0-100 scale, calibrated against the thresholds in
    // config/securityConfig.js (suspicious=25, critical/throttle=60,
    // block=85) so that routine velocity deviations on normal endpoints
    // stay under "suspicious," while the same deviation against a
    // destructive endpoint, or a handful of unresolved login attempts,
    // crosses into throttle/block territory. See the worked examples in
    // computeScore() below.
    velocityPointScale: 5,

    // Weight applied to any endpoint without an explicit entry below;
    // defaults to "normal" risk.
    defaultEndpointWeight: 1,

    endpointWeights: {
        // ---- Normal endpoints (1x) ----
        "/api/students/view": 1,
        "/api/subjects/view": 1,

        // ---- Elevated endpoints (2x) ----
        "/api/login": 2,          // classic brute-force / credential-stuffing target
        "/api/verify-otp": 2,     // second factor for admin login (see authController.js);
                                   // weighted level with /api/login rather than higher despite
                                   // its much smaller 6-digit keyspace - core/monitor.js already
                                   // folds OTP guesses into the same loginAttempts counter as
                                   // password guesses, so a higher weight here would compound
                                   // with that shared counter and throttle a legitimate user off
                                   // a single mistyped-then-corrected code; matching /api/login's
                                   // weight instead reuses its already-tuned 5th/8th-attempt
                                   // throttle/block cadence (see the worked examples in
                                   // computeScore() below) without new tuning.
        "/api/admin/logs": 2,     // exposes the security audit trail itself
        "/api/students": 2,       // POST creates a new student record
        "/api/subjects": 2,       // POST creates a new subject record
        "/api/grades": 2,         // POST creates a new grade record

        // ---- Sensitive, single-record mutation endpoints (3x) ----
        "/api/students/:id": 3,   // PUT (edit) and DELETE (remove) both normalize here
        "/api/subjects/:id": 3,
        "/api/grades/:id": 3,
        "/api/admin/blocked-devices/unblock": 3, // lifts a block early and can revoke a live session

        // ---- Destructive / infrastructure-wide endpoints (4x) ----
        "/api/settings/backup": 4,
        "/api/settings/restore": 4, // a bad restore can silently overwrite live data
        "/api/admin/backup": 4,     // exports every table - student records, grades, the audit trail - at once
        "/api/admin/accounts": 4,   // minting a new admin is a standing capability grant

        // ---- Demo tooling ----
        "/api/demo/ping": 1        // pinned at baseline weight so "Simulate Attack"
                                    // (public/admin_dashboard.js) demonstrates the
                                    // velocity factor in isolation
    }
};
Object.freeze(defaultWevaConfig.endpointWeights);
Object.freeze(defaultWevaConfig);

/**
 * Computes the anomaly score for the current request using the Weighted
 * Endpoint & Velocity Algorithm (WEVA):
 *
 *     score = velocityIncrement * endpointWeight * failRateFactor * velocityPointScale
 *
 * Worked examples using `defaultWevaConfig` and this app's real thresholds
 * (config/securityConfig.js: suspicious=25, critical/throttle=60, block=85;
 * admins get +15 tolerance on critical/block - see
 * core/decisionEngine.js) - pinned exactly as regression tests in
 * core/scorer.test.js:
 *
 *   - Idle browsing: velocityIncrement=0 => score=0. ALLOW.
 *
 *   - Device moving 3 req/sec above its own baseline, on a normal (1x)
 *     endpoint, no outstanding login attempts:
 *       3 * 1 * 1 * 5 = 15  -> below "suspicious" (25). ALLOW.
 *
 *   - The identical +3 req/sec burst against DELETE /api/students/:id (3x):
 *       3 * 3 * 1 * 5 = 45  -> LOG-level attention (>= 25, < 60).
 *
 *   - A device's 5th rapid login attempt (4 prior unresolved attempts,
 *     failRateFactor = 1 + 4*0.5 = 3; velocity floored to
 *     minVelocityFloor=2; endpoint weight 2x for /api/login; pre-auth so
 *     no admin tolerance applies):
 *       2 * 2 * 3 * 5 = 60  -> THROTTLE.
 *
 *   - The same device's 7th attempt (6 prior, failRateFactor = 4):
 *       2 * 2 * 4 * 5 = 80  -> still THROTTLE (below block=85).
 *
 *   - Its 8th attempt (7 prior, failRateFactor = 1 + 7*0.5 = 4.5) is the
 *     first BLOCK:
 *       2 * 2 * 4.5 * 5 = 90 -> BLOCK.
 *     (The 9th, at 8 prior, reaches the 100 ceiling - also BLOCK, but
 *     not the first one.)
 *
 * The function returns the itemized factors alongside the final score, not
 * just the number, so every score is independently auditable:
 * middleware/securityMiddleware.js persists the breakdown, and the admin
 * dashboard renders it in the Security Logs table.
 *
 * @param {object} currentFeatures  Output of core/monitor.js#getFeatures():
 *                                  { requestRate, loginAttempts, endpoint }
 * @param {object} baselineFeatures Output of core/profiler.js#getBaseline():
 *                                  { requestRate, previousScore }
 * @param {{minVelocityFloor: number, failRateIncrement: number, velocityPointScale: number, defaultEndpointWeight: number, endpointWeights: Record<string, number>}} [config] - WEVA tuning; defaults to `defaultWevaConfig` (this app's real values) when omitted, so every existing call site is unaffected.
 * @returns {{score: number, breakdown: {velocityIncrement: number, endpointWeight: number, failRateFactor: number, scale: number, formula: string}}}
 *          `score` is the integer anomaly score, clamped to 0-100.
 *          `breakdown` is every factor that produced it, plus a
 *          ready-to-log/display formula string.
 */
export function computeScore(currentFeatures, baselineFeatures, config = defaultWevaConfig) {
    const velocityIncrement = getVelocityIncrement(currentFeatures, baselineFeatures, config.minVelocityFloor);
    const endpointWeight = getEndpointWeight(currentFeatures.endpoint, config.endpointWeights, config.defaultEndpointWeight);
    const failRateFactor = getFailRateFactor(currentFeatures.loginAttempts, config.failRateIncrement);

    let score = velocityIncrement * endpointWeight * failRateFactor * config.velocityPointScale;

    if (score < 0) score = 0;
    score = Math.min(Math.round(score), 100);

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
 * Rounds a factor to 2 decimal places for display/logging, since the raw
 * requestRate math produces long floats.
 *
 * @param {number} n - Value to round.
 * @returns {number}
 */
function round2(n) {
    return Math.round(n * 100) / 100;
}

/**
 * Fixed maximal-severity score for a network-policy violation - an IP
 * outside ALLOWED_ADMIN_IPS reaching an admin-only endpoint at all (see
 * middleware/ipWhitelistMiddleware.js) - as opposed to computeScore()
 * above, which *derives* a graduated score from behavioral features
 * accumulated over one or more requests.
 *
 * There is nothing to accumulate here: unlike a single mistyped
 * password, which is presumed innocent until a pattern of repetition
 * says otherwise, a request against admin infrastructure from outside
 * the whitelisted network is, by policy, already conclusive on the
 * first attempt - the network origin itself is the violation, not a
 * rate of requests. The score is therefore asserted at the scale's
 * ceiling (100) rather than computed: the same value computeScore()
 * only reaches after a sustained brute-force burst (see its 9th-attempt
 * worked example above), here reached in one request so it maps
 * unambiguously onto the *existing* CRITICAL/BLOCK band
 * (config/securityConfig.js: block=85) instead of introducing a
 * separate severity scale a reader would have to learn.
 *
 * Returns the same {score, breakdown} shape as computeScore() so
 * callers can persist it through the identical audit-logging code path
 * as every other WEVA verdict (AnomalyScore + SecurityAction +
 * BehaviorLog, all keyed off `breakdown.formula`).
 *
 * @param {string} reason - Human-readable detail folded into the returned formula string for the audit trail (e.g. the offending IP and path).
 * @returns {{score: number, breakdown: {formula: string}}}
 */
export function getIntrusionScore(reason) {
    return {
        score: 100,
        breakdown: {
            formula: `NETWORK POLICY VIOLATION (instant max score, no accumulation needed) - ${reason}`
        }
    };
}
