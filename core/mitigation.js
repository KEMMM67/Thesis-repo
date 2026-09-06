import { securityConfig } from "../config/securityConfig.js";

/**
 * Seconds remaining until `date`, rounded UP so a client-side countdown
 * derived from this value never reaches zero before the server-side block
 * actually lifts - rounding down could let the countdown hit 0 a fraction
 * of a second early, re-enabling a form for one more request that would
 * still get 403'd. Floored at 0 so an already-past date (clock drift, or a
 * block that is seconds from expiring) never produces a negative
 * countdown.
 *
 * @param {Date} date
 * @returns {number}
 */
function secondsUntil(date) {
    return Math.max(0, Math.ceil((date.getTime() - Date.now()) / 1000));
}

/**
 * Sends the fixed BLOCK rejection body, including `retryAfterSeconds` - how
 * long this specific lockout has left. Without this, a frontend has no way
 * to know the real remaining duration and can only guess (this app's
 * frontend previously guessed 3 seconds and reloaded the page, which had
 * nothing to do with the real lockout length and just let a confused user
 * retry straight into another BLOCK). Shared by both call sites below - the
 * "already blocked" fast path and the "just crossed the threshold" path -
 * so the response shape never drifts between them.
 *
 * @param {import("express").Response} res
 * @param {Date} blockedUntil
 * @returns {void}
 */
function sendBlockedResponse(res, blockedUntil) {
    res.status(403).json({
        success: false,
        message: "CRITICAL THREAT: Brute force behavior detected. IP temporarily blocked.",
        retryAfterSeconds: secondsUntil(blockedUntil)
    });
}

/**
 * Enforces the Decision Engine's verdict (core/decisionEngine.js) against a
 * request's originating identifier.
 *
 * State is persisted via the injected `ipTrackingStore` (see
 * core/ports.js#IpTrackingStore; the default, Prisma-backed
 * implementation is adapters/prisma/ipTrackingStore.js) rather than an
 * in-memory map, so that blocks survive a server restart, remain
 * queryable by the admin dashboard's Blocked Devices panel, and stay
 * consistent if the server is ever scaled to more than one process. This
 * function itself has no idea what actually backs that store - Postgres
 * today, anything else tomorrow.
 *
 * Note: `identifier` is populated from the `x-device-id` header (falling
 * back to `req.ip` - see core/monitor.js) and is not necessarily a true IP
 * address, despite `IpTrackingStore` implementations typically keying on
 * an `ipAddress`-named column. This mismatch predates this function and is
 * documented here rather than silently carried forward.
 *
 * A BLOCK response (fresh or an already-active lockout) includes
 * `retryAfterSeconds`, computed from the real `blockedUntil` rather than a
 * fixed guess, so the frontend can run an honest countdown instead of
 * reloading on a timer unrelated to how long the lockout actually lasts
 * (see public/admin_login.js and public/script.js).
 *
 * @param {"BLOCK"|"THROTTLE"|"LOG"|"ALLOW"} decision - Verdict from decideAction().
 * @param {import("express").Response} res - Response used to short-circuit blocked/throttled requests.
 * @param {string} identifier - Device/IP identifier the verdict applies to.
 * @param {import("./ports.js").IpTrackingStore} ipTrackingStore - Injected block-tracking store.
 * @returns {Promise<boolean>} `true` if the request was terminated (blocked
 *          or throttled) and the caller must not proceed; `false` otherwise.
 */
export async function applyMitigation(decision, res, identifier, ipTrackingStore) {
    const now = new Date();

    // An existing, still-active lockout takes precedence over the current
    // request's own verdict - an already-blocked device stays rejected even
    // on a request that would otherwise score as ALLOW/LOG.
    const existing = await ipTrackingStore.findStatus(identifier);

    if (existing?.isBlocked && existing.blockedUntil && existing.blockedUntil > now) {
        sendBlockedResponse(res, existing.blockedUntil);
        return true;
    }

    if (decision === 'BLOCK') {
        const blockedUntil = new Date(now.getTime() + securityConfig.mitigation.temporaryBlockMs);
        await ipTrackingStore.block(identifier, blockedUntil);
        sendBlockedResponse(res, blockedUntil);
        return true;

    } else if (decision === 'THROTTLE') {
        // Not persisted: THROTTLE is a soft, momentary penalty, not a
        // standing block worth recording in the store.
        res.status(429).json({
            success: false,
            message: "Too many attempts. Please wait.",
            retryAfter: 15
        });
        return true;
    }

    // ALLOW/LOG require no mitigation. A block is recorded only once a
    // device earns a BLOCK, so the store stays a record of genuine
    // incidents rather than every request seen.
    if (existing && (!existing.isBlocked || (existing.blockedUntil && existing.blockedUntil <= now))) {
        // Lockout has expired - clear the stale flag so the dashboard stops
        // reporting the device as blocked. Best-effort; failure here does
        // not affect the current request (see IpTrackingStore#clear).
        await ipTrackingStore.clear(identifier);
    }

    return false;
}
