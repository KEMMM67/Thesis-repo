import { securityConfig } from "../config/securityConfig.js";

/**
 * Default role-based tolerance layered on top of the base thresholds.
 * Admins receive +15 on the throttle and block thresholds relative to
 * other roles, since legitimate bulk operations (e.g. batch grade entry)
 * naturally produce a higher request velocity than a single-record
 * student action.
 *
 * Expressed as a function rather than an `if (role === 'admin')` branch
 * baked directly into decideAction(), so a caller can define tolerance
 * for any role scheme of their own (e.g. a "faculty" role with its own
 * bulk-operation patterns) by supplying a different `roleTolerance` in
 * their config, without this file's own logic needing to know that role
 * exists.
 *
 * @param {string} role - Requesting user's role.
 * @returns {number} Threshold tolerance to add, in points.
 */
function defaultRoleTolerance(role) {
    return role === 'admin' ? 15 : 0;
}

/**
 * Default decision configuration, used whenever decideAction() is called
 * with no third argument - which is how every call site in this app
 * invokes it today (see middleware/securityMiddleware.js). `thresholds` is
 * a live reference to config/securityConfig.js's own thresholds object, so
 * this app's .env-driven tuning
 * (SECURITY_THRESHOLD_SUSPICIOUS/CRITICAL/BLOCK) keeps working exactly as
 * before; `roleTolerance` is the admin +15 rule above. A different host
 * application can pass its own `{ thresholds, roleTolerance }` shape
 * entirely and this file never needs to change.
 *
 * Frozen at the top level so nothing can repoint `.thresholds` or
 * `.roleTolerance` on the shared default out from under every caller that
 * relies on it - a config object meant to be shared should not be
 * silently editable in place. Not deep-frozen: `.thresholds` itself is
 * config/securityConfig.js's own object, which that module owns.
 */
export const defaultDecisionConfig = {
    thresholds: securityConfig.thresholds,
    roleTolerance: defaultRoleTolerance
};
Object.freeze(defaultDecisionConfig);

/**
 * Maps an anomaly score to a mitigation verdict by comparing it against
 * `config`'s thresholds, adjusted by `config.roleTolerance(role)`.
 *
 * Administrators receive a tolerance (by default, +15) on the throttle
 * and block thresholds relative to other roles, since legitimate bulk
 * operations (e.g. batch grade entry) naturally produce a higher request
 * velocity than a single-record student action. The "suspicious"/LOG
 * threshold is never adjusted by role - every role's activity is worth
 * logging at the same sensitivity; only the throttle/block *enforcement*
 * point moves.
 *
 * @param {number} score - Anomaly score computed by core/scorer.js, 0-100.
 * @param {string} role - Requesting user's role (e.g. "admin", "student").
 * @param {{thresholds: {suspicious: number, critical: number, block: number}, roleTolerance?: (role: string) => number}} [config] - Decision configuration; defaults to `defaultDecisionConfig` (this app's real thresholds and the admin +15 rule) when omitted, so every existing call site is unaffected.
 * @returns {"BLOCK"|"THROTTLE"|"LOG"|"ALLOW"} Mitigation verdict for
 *          core/mitigation.js to enforce.
 */
export function decideAction(score, role, config = defaultDecisionConfig) {
    const tolerance = config.roleTolerance ? config.roleTolerance(role) : 0;
    const blockThreshold = config.thresholds.block + tolerance;
    const throttleThreshold = config.thresholds.critical + tolerance;
    const logThreshold = config.thresholds.suspicious;

    if (score >= blockThreshold) {
        return 'BLOCK';
    } else if (score >= throttleThreshold) {
        return 'THROTTLE';
    } else if (score >= logThreshold) {
        return 'LOG';
    } else {
        return 'ALLOW';
    }
}
