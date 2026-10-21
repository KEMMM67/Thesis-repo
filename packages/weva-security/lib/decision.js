/**
 * @fileoverview Score -> verdict, from the thesis build's
 * core/decisionEngine.js. The thesis build also gives admins +15 on the
 * THROTTLE and BLOCK thresholds; this package scores clients before they sign
 * in, so it has no roles.
 */

export const DEFAULT_THRESHOLDS = Object.freeze({
    suspicious: 25, // LOG: let through and reported
    critical: 60,   // THROTTLE: 429 + Retry-After
    block: 85       // BLOCK: 403, client blocked for blockMs
});

/**
 * @param {number} score - 0-100, from computeScore().
 * @param {{suspicious: number, critical: number, block: number}} [thresholds]
 * @returns {'ALLOW'|'LOG'|'THROTTLE'|'BLOCK'}
 */
export function decideAction(score, thresholds = DEFAULT_THRESHOLDS) {
    if (score >= thresholds.block) return 'BLOCK';
    if (score >= thresholds.critical) return 'THROTTLE';
    if (score >= thresholds.suspicious) return 'LOG';
    return 'ALLOW';
}
