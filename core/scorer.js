// =====================================================================
// WEIGHTED ENDPOINT & VELOCITY ALGORITHM (WEVA)
// =====================================================================
// This module replaces the original flat "speed + attempt count" scorer
// with a single multiplicative formula:
//
//     score = velocityIncrement * endpointWeight * failRateFactor * VELOCITY_POINT_SCALE
//
// The three factors are multiplied together (not added) because risk is
// *compounding*, not merely additive: a fast request rate is only mildly
// interesting on a harmless endpoint, but the SAME speed against a
// destructive endpoint (e.g. deleting a student record, or backing up /
// restoring the database) is a much bigger deal - and worse again if
// that device also has a trail of recent unresolved login attempts
// behind it. Multiplying lets each factor amplify the others instead of
// just stacking on top of them additively.
//
//   score = velocityIncrement  x  endpointWeight  x  failRateFactor
//           ------------------    --------------     ---------------
//           "How much faster      "How dangerous      "How many recent
//            than usual is this    is this specific    unresolved login
//            device moving?"       endpoint to abuse?" attempts trail
//                                                       this device?"
//
// NOTE on the old "grace period": the previous version had a special
// case exempting a user's very first login attempt from scoring. That
// special case is no longer needed - it falls out of the math for free.
// On a device's first-ever request there is no prior request timestamp
// (so requestRate = 0) and no prior login attempts (so loginAttempts =
// 0), which drives velocityIncrement to 0. Since the three factors are
// MULTIPLIED, a velocityIncrement of 0 forces the whole score to 0
// regardless of endpoint weight, exactly reproducing the old exemption
// without a special-cased branch.
//
// Each factor is documented in detail immediately above the code that
// computes it, in the same order they appear in the formula.
// =====================================================================

// ---------------------------------------------------------------------
// FACTOR 1: REQUEST VELOCITY INCREMENT
// ---------------------------------------------------------------------
// core/monitor.js reports the device's current request velocity in
// requests/second (currentFeatures.requestRate) alongside its learned,
// slow-moving personal-average velocity (baselineFeatures.requestRate,
// maintained by the EMA in core/profiler.js). The "increment" is how far
// ABOVE that personal baseline the device is currently moving:
//
//   velocityIncrement = max(0, currentRate - baselineRate)
//
// Only positive deviations count - a device that slows down relative to
// its own history is never penalized, only one that speeds up.
//
// SAFETY FLOOR: a purely multiplicative formula has one sharp edge -
// multiplying by a velocity of zero always yields a score of zero, no
// matter how suspicious the other two factors are. A slow, deliberately
// -paced brute-force attempt (one attempt every few seconds, comfortably
// inside "normal" velocity) could otherwise hide behind a near-zero
// velocity term indefinitely. To close that gap, whenever the device has
// outstanding, unresolved login attempts (loginAttempts > 0 - the same
// signal FACTOR 3 uses below), the velocity term is floored to
// MIN_VELOCITY_FLOOR so those attempts can still surface a score even at
// low speed.
//
// This floor deliberately does NOT help a slow attacker probing a
// *non*-login endpoint with no attempt trail (e.g. one DELETE request
// every 40 seconds against /api/students/:id). Detecting purely
// volume-based, low-and-slow abuse of arbitrary endpoints is out of
// scope for a rate-based algorithm - it would need a complementary
// long-window request counter as future work, which is a reasonable and
// honest limitation to name in a thesis defense rather than paper over.
const MIN_VELOCITY_FLOOR = 2;

function getVelocityIncrement(currentFeatures, baselineFeatures) {
    const currentRate = currentFeatures.requestRate || 0;
    const baselineRate = baselineFeatures.requestRate || 0;

    let increment = currentRate - baselineRate;
    if (increment < 0) increment = 0;

    if ((currentFeatures.loginAttempts || 0) > 0) {
        increment = Math.max(increment, MIN_VELOCITY_FLOOR);
    }

    return increment;
}

// ---------------------------------------------------------------------
// FACTOR 2: ENDPOINT SENSITIVITY WEIGHT
// ---------------------------------------------------------------------
// Not every endpoint carries the same blast radius if abused. A script
// hammering a read-only "view" route is noisy but low-risk; the same
// request rate against a route that deletes a student record, or backs
// up/restores the whole database, is a genuine incident. endpointWeights
// maps a normalized request path to a multiplier that encodes exactly
// that difference in stakes:
//
//    1x  ->  routine, read-mostly, low blast-radius endpoints
//            (also the default for any endpoint with no explicit entry)
//    2x  ->  authentication / other moderately sensitive endpoints
//    3x  ->  endpoints that create or mutate a single persistent record
//    4x  ->  destructive or infrastructure-wide endpoints (irreversible,
//            or affecting the whole system rather than one record)
//
// Paths are matched after normalizePath() collapses dynamic ID segments -
// numeric IDs, lettered student codes ("A23-00001"), and subject codes
// ("SE301") alike - down to a single ":id" placeholder, so
// "/api/students/42", "/api/students/A23-00001", and
// "/api/subjects/SE301" all resolve to their route's dictionary entry
// instead of silently falling through to the default weight.
//
// DESIGN NOTE - PUT vs DELETE sharing one path (e.g. "/api/students/:id",
// "/api/subjects/:id"): both actions mutate a *single* record, so both
// are deliberately treated as the same "3x - single record" risk tier
// rather than splitting DELETE out higher. Distinguishing them would
// require the HTTP method to be threaded through from
// middleware/securityMiddleware.js down to this scorer, and that file
// (and its Promise.allSettled audit-logging block) is intentionally left
// untouched by this change - see core/monitor.js for how the endpoint
// string alone reaches this module. The 4x tier is therefore reserved
// purely for actions with *system-wide* blast radius (DB backup/
// restore), which is a clean, easy-to-defend rule on its own: "weight
// scales with blast radius - one record vs. the whole database."
const endpointWeights = {
    // ---- Normal endpoints (1x) ----
    "/api/students/view": 1,
    "/api/subjects/view": 1,

    // ---- Elevated endpoints (2x) ----
    "/api/login": 2,          // classic brute-force / credential-stuffing target
    "/api/admin/logs": 2,     // exposes the security audit trail itself
    "/api/students": 2,       // POST here creates a brand-new student record
    "/api/subjects": 2,       // POST here creates a brand-new subject record

    // ---- Sensitive, single-record mutation endpoints (3x) ----
    "/api/students/:id": 3,   // PUT (edit) and DELETE (remove) both normalize here
    "/api/subjects/:id": 3,   // same reasoning - covers subject edit AND delete

    // ---- Destructive / infrastructure-wide endpoints (4x) ----
    "/api/settings/backup": 4,
    "/api/settings/restore": 4  // a bad restore can silently overwrite live
                                 // data, arguably making it even higher-stakes
                                 // than backup despite sharing its weight -
                                 // see the route comment in server.js
};

// Weight applied to any endpoint that has no explicit entry above.
// Unknown routes default to "normal" (1x) rather than either
// automatically safe (0x, which would erase them from scoring entirely)
// or automatically dangerous (which would make adding any new harmless
// route a silent, self-inflicted security incident).
const DEFAULT_ENDPOINT_WEIGHT = 1;

// Collapses dynamic path segments so the dictionary above only needs one
// entry per *route pattern* instead of one per concrete ID. Handles
// purely numeric database IDs ("/api/students/42"), the school's
// alphanumeric student ID codes ("/api/students/A23-00001"), and subject
// codes ("/api/subjects/SE301") - 2 to 4 letters directly followed by 3
// digits, no hyphen, matching the codes already used throughout the
// dashboard (SE301, IAS301, HCI101, ...).
function normalizePath(rawPath) {
    return rawPath.replace(
        /\/([0-9]+|[A-Za-z]\d{2}-\d{4,5}|[A-Za-z]{2,4}\d{3})(?=\/|$)/g,
        "/:id"
    );
}

function getEndpointWeight(endpoint) {
    if (!endpoint) return DEFAULT_ENDPOINT_WEIGHT;
    const normalized = normalizePath(endpoint);
    return endpointWeights[normalized] ?? endpointWeights[endpoint] ?? DEFAULT_ENDPOINT_WEIGHT;
}

// ---------------------------------------------------------------------
// FACTOR 3: ERROR / FAIL RATE MULTIPLIER ("if applicable")
// ---------------------------------------------------------------------
// core/monitor.js currently tracks exactly one genuine outcome-aware
// retry signal: loginAttempts counts requests to the login endpoint that
// have happened *since the device's last successful login* (a success
// calls resetFeatures() in server.js and zeroes the counter out). An
// escalating count that never gets reset is therefore a solid proxy for
// "this device keeps failing / retrying" - exactly what a fail rate is
// meant to capture, without needing a separate failure-tracking system.
//
// For any request where that signal does not apply - i.e. the device
// currently has no outstanding attempts (loginAttempts === 0) - the
// multiplier resolves to EXACTLY 1, making it a true no-op. That is what
// "if applicable" means mathematically: the factor only ever amplifies
// the score above its velocity x weight baseline, and otherwise gets out
// of the way entirely instead of distorting normal traffic.
//
//   failRateFactor = 1 + (loginAttempts * FAIL_RATE_INCREMENT)
//
// FAIL_RATE_INCREMENT (0.5) means every unresolved attempt adds another
// half-multiple of amplification: 2 outstanding attempts => 2x, 4 => 3x,
// 8 => 5x, compounding with velocity and endpoint weight as the streak
// grows.
const FAIL_RATE_INCREMENT = 0.5;

function getFailRateFactor(loginAttempts) {
    const attempts = Math.max(0, loginAttempts || 0);
    return 1 + (attempts * FAIL_RATE_INCREMENT);
}

// ---------------------------------------------------------------------
// SCALE CONSTANT
// ---------------------------------------------------------------------
// Converts the raw (velocity x weight x failRate) product into score
// "points" on the system's existing 0-100 scale, so results line up with
// the thresholds already defined in config/securityConfig.js
// (suspicious=25, critical/throttle=60, block=85). Chosen so that a
// device moving a few req/sec faster than its own baseline on a normal
// (1x) endpoint stays under "suspicious" (mostly noise), while the same
// deviation against a 4x destructive endpoint, or a handful of
// unresolved login attempts, is enough to cross into throttle/block
// territory. See the worked examples in the computeScore() docblock
// below for the exact numbers.
const VELOCITY_POINT_SCALE = 5;

/**
 * Computes the anomaly score for the current request using the Weighted
 * Endpoint & Velocity Algorithm (WEVA):
 *
 *     score = velocityIncrement * endpointWeight * failRateFactor * VELOCITY_POINT_SCALE
 *
 * Worked examples (thresholds from config/securityConfig.js: suspicious=25,
 * critical/throttle=60, block=85; admins get +15 tolerance on
 * critical/block - see core/decisionEngine.js):
 *
 *   - Idle browsing: velocityIncrement=0 (no deviation from personal
 *     baseline) => score=0 no matter the endpoint weight. ALLOW.
 *
 *   - A device moving 3 req/sec faster than its own baseline, clicking
 *     around a normal (1x) page, no outstanding login attempts:
 *       3 * 1 * 1 * 5 = 15  -> below "suspicious" (25). ALLOW.
 *
 *   - The identical +3 req/sec burst, but aimed at DELETE
 *     /api/students/:id (3x) instead:
 *       3 * 3 * 1 * 5 = 45  -> LOG-level attention (>= 25, < 60).
 *
 *   - A brand-new device's 5th rapid login attempt (4 prior unresolved
 *     attempts, so failRateFactor = 1 + 4*0.5 = 3; velocity floored to
 *     MIN_VELOCITY_FLOOR=2; endpoint weight 2x for /api/login; pre-auth
 *     so no admin tolerance applies):
 *       2 * 2 * 3 * 5 = 60  -> THROTTLE.
 *
 *   - The same device's 9th rapid login attempt (8 prior, failRateFactor
 *     = 1 + 8*0.5 = 5):
 *       2 * 2 * 5 * 5 = 100 -> BLOCK.
 *
 * @param {object} currentFeatures  Output of core/monitor.js#getFeatures():
 *                                  { requestRate, loginAttempts, endpoint }
 * @param {object} baselineFeatures Output of core/profiler.js#getBaseline():
 *                                  { requestRate, previousScore }
 * @returns {number} Integer anomaly score clamped to the 0-100 range.
 */
export function computeScore(currentFeatures, baselineFeatures) {
    const velocityIncrement = getVelocityIncrement(currentFeatures, baselineFeatures);
    const endpointWeight = getEndpointWeight(currentFeatures.endpoint);
    const failRateFactor = getFailRateFactor(currentFeatures.loginAttempts);

    let score = velocityIncrement * endpointWeight * failRateFactor * VELOCITY_POINT_SCALE;

    // Ensure the final score remains within the operational bounds (0 to 100)
    if (score < 0) score = 0;
    return Math.min(Math.round(score), 100);
}
