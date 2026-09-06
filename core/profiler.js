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
