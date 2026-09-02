import { securityConfig } from "../config/securityConfig.js";

/**
 * Maps an anomaly score to a mitigation verdict by comparing it against the
 * system's configured thresholds (config/securityConfig.js).
 *
 * Administrators receive a +15 tolerance on the throttle and block
 * thresholds relative to other roles, since legitimate bulk operations
 * (e.g. batch grade entry) naturally produce a higher request velocity
 * than a single-record student action.
 *
 * @param {number} score - Anomaly score computed by core/scorer.js, 0-100.
 * @param {string} role - Requesting user's role (e.g. "admin", "student").
 * @returns {"BLOCK"|"THROTTLE"|"LOG"|"ALLOW"} Mitigation verdict for
 *          core/mitigation.js to enforce.
 */
export function decideAction(score, role) {
    let blockThreshold = securityConfig.thresholds.block;
    let throttleThreshold = securityConfig.thresholds.critical;
    let logThreshold = securityConfig.thresholds.suspicious;

    if (role === 'admin') {
        blockThreshold += 15;
        throttleThreshold += 15;
    }

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
