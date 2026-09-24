import { securityConfig } from "../config/securityConfig.js";
import { MemoryStateStore } from "./stateStore.js";

/**
 * Backing store for each user's learned behavioral baseline. Previously a
 * bare module-level object (`baselines`) with the same unbounded-growth
 * problem as core/monitor.js's `activeUsers` - see core/stateStore.js and
 * the equivalent comment on monitor.js's own store for the full rationale.
 */
const store = new MemoryStateStore();

/**
 * Retrieves a user's baseline profile, initializing a default one on first
 * access.
 *
 * @param {string} user - User identifier.
 * @returns {{requestRate: number, previousScore: number}}
 */
export function getBaseline(user) {
    return store.getOrCreate(user, () => ({
        requestRate: 0,
        previousScore: 0
    }));
}

/**
 * Updates a user's baseline request rate using an Exponential Moving
 * Average (EMA). EMA is used instead of a simple running average because it
 * weights recent behavior more heavily while still retaining historical
 * context, letting the baseline adapt to gradual, legitimate changes in a
 * user's usage pattern without being thrown off by a single outlier
 * request.
 *
 * Only feed this traffic WEVA let through. The baseline is the "normal"
 * that velocity is judged against, so learning from a request WEVA
 * throttled or blocked teaches it that the attack is normal - baseline
 * poisoning. middleware/securityMiddleware.js therefore calls this only for
 * an identity whose own verdict was ALLOW or LOG. Before that gate existed,
 * two reproduced attacks got through:
 *
 *   - A steady 5 req/s flood of admin edits (weight 3): the 3rd request
 *     scored 5 x 3 x 5 = 75 (THROTTLE), but with alpha 0.1 per request the
 *     baseline caught up within a few requests, the score fell to LOG and
 *     then ALLOW, and 599 of 600 requests passed. With the gate, the
 *     throttled requests are never learned, the baseline stays near 0, and
 *     every request keeps scoring 75: THROTTLE.
 *   - A 20 req/s flood: blocked on its 3rd request, but it kept learning
 *     during the 60 s lockout, so once the block lifted its current rate
 *     matched its baseline, the increment was ~0, and ~1,800 requests passed
 *     in the next 90 s. With the gate, its baseline stays at 0 and it is
 *     blocked again the moment the lockout ends.
 *
 * The residual limit: a patient attacker who raises the rate in steps
 * small enough to stay at LOG is still learned as normal (a slow
 * "boiling frog" ramp). That is inherent to any adaptive baseline; per-role
 * absolute ceilings or a long-window volume counter are the future-work
 * answer.
 *
 * @param {string} user - User identifier whose baseline is updated.
 * @param {{requestRate: number}} currentFeatures - Current-request features from core/monitor.js#getFeatures().
 * @returns {void}
 */
export function updateBaseline(user, currentFeatures) {
    const baseline = getBaseline(user);

    // alpha is the learning rate: higher values weight recent behavior more
    // heavily; lower values make the baseline more resistant to change.
    const alpha = securityConfig.emaAlpha || 0.1;

    baseline.requestRate = (currentFeatures.requestRate * alpha) + (baseline.requestRate * (1 - alpha));
}
