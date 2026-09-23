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
 * request's originating identifier(s).
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
 * Note: an identifier is either a validated `x-device-id` or a normalized IP
 * (see middleware/clientIdentity.js), so it is not necessarily a true IP
 * address, despite `IpTrackingStore` implementations typically keying on an
 * `ipAddress`-named column. This naming mismatch predates this function and
 * is documented here rather than silently carried forward. The two kinds can
 * never collide: a valid device ID cannot contain the "." or ":" every IP has.
 *
 * A BLOCK response (fresh or an already-active lockout) includes
 * `retryAfterSeconds`, computed from the real `blockedUntil` rather than a
 * fixed guess, so the frontend can run an honest countdown instead of
 * reloading on a timer unrelated to how long the lockout actually lasts
 * (see public/admin_login.js and public/script.js).
 *
 * A request can carry more than one identity (see
 * middleware/securityMiddleware.js: the client-supplied device ID and, before
 * login, the server-observed IP). The request is refused if ANY of them has
 * an active block - otherwise a bot blocked by IP could walk straight back in
 * under a new device ID. A new BLOCK, though, is recorded against the FIRST
 * identifier only: the identity whose score produced the verdict. Blocking
 * every identity would mean one device's misbehaviour locks out everyone
 * sharing its IP; blocking only the responsible one keeps the blast radius to
 * exactly what was measured.
 *
 * @param {"BLOCK"|"THROTTLE"|"LOG"|"ALLOW"} decision - Verdict from decideAction().
 * @param {import("express").Response} res - Response used to short-circuit blocked/throttled requests.
 * @param {string|string[]} identifiers - Identifier(s) the verdict applies to, the responsible one first. A single string is accepted for callers with one identity.
 * @param {import("./ports.js").IpTrackingStore} ipTrackingStore - Injected block-tracking store.
 * @returns {Promise<boolean>} `true` if the request was terminated (blocked
 *          or throttled) and the caller must not proceed; `false` otherwise.
 */
export async function applyMitigation(decision, res, identifiers, ipTrackingStore) {
    const ids = Array.isArray(identifiers) ? identifiers : [identifiers];
    const now = new Date();

    // An existing, still-active lockout takes precedence over the current
    // request's own verdict - an already-blocked identity stays rejected even
    // on a request that would otherwise score as ALLOW/LOG. With several
    // active blocks, the countdown reports the one that lifts last, since the
    // request is refused until all of them have.
    const statuses = await Promise.all(ids.map(id => ipTrackingStore.findStatus(id)));
    const activeUntil = statuses
        .filter(status => status?.isBlocked && status.blockedUntil && status.blockedUntil > now)
        .map(status => status.blockedUntil)
        .sort((a, b) => b - a)[0];

    if (activeUntil) {
        sendBlockedResponse(res, activeUntil);
        return true;
    }

    if (decision === 'BLOCK') {
        const blockedUntil = new Date(now.getTime() + securityConfig.mitigation.temporaryBlockMs);
        await ipTrackingStore.block(ids[0], blockedUntil);
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

    // ALLOW/LOG require no mitigation. A block is recorded only once an
    // identity earns a BLOCK, so the store stays a record of genuine
    // incidents rather than every request seen.
    //
    // A lockout that has expired is cleared so the dashboard stops reporting
    // it as blocked. Only a flag that is still set needs clearing: this used
    // to "clear" rows that were already clear too, costing a pointless UPDATE
    // on every request from any identity that had ever been blocked - now
    // doubled by checking two identities per login attempt. Best-effort;
    // failure here does not affect the current request (see
    // IpTrackingStore#clear).
    await Promise.all(ids.map((id, i) => {
        const status = statuses[i];
        const expired = status?.isBlocked && status.blockedUntil && status.blockedUntil <= now;
        return expired ? ipTrackingStore.clear(id) : null;
    }));

    return false;
}
