import { securityConfig } from "../config/securityConfig.js";
import prisma from "../config/prisma.js";

/**
 * Enforces the Decision Engine's verdict (core/decisionEngine.js) against a
 * request's originating identifier.
 *
 * State is persisted via `prisma.ipTracking` rather than an in-memory map so
 * that blocks survive a server restart, remain queryable by the admin
 * dashboard's Blocked Devices panel, and stay consistent if the server is
 * ever scaled to more than one process.
 *
 * Note: `identifier` is populated from the `x-device-id` header (falling
 * back to `req.ip` - see core/monitor.js) and is not necessarily a true IP
 * address, though it is persisted in a column named `ipAddress`. This
 * mismatch predates this function and is documented here rather than
 * silently carried forward.
 *
 * @param {"BLOCK"|"THROTTLE"|"LOG"|"ALLOW"} decision - Verdict from decideAction().
 * @param {import("express").Response} res - Response used to short-circuit blocked/throttled requests.
 * @param {string} identifier - Device/IP identifier the verdict applies to.
 * @returns {Promise<boolean>} `true` if the request was terminated (blocked
 *          or throttled) and the caller must not proceed; `false` otherwise.
 */
export async function applyMitigation(decision, res, identifier) {
    const now = new Date();

    // An existing, still-active lockout takes precedence over the current
    // request's own verdict - an already-blocked device stays rejected even
    // on a request that would otherwise score as ALLOW/LOG.
    const existing = await prisma.ipTracking.findUnique({ where: { ipAddress: identifier } });

    if (existing?.isBlocked && existing.blockedUntil && existing.blockedUntil > now) {
        res.status(403).json({
            success: false,
            message: "CRITICAL THREAT: Brute force behavior detected. IP temporarily blocked."
        });
        return true;
    }

    if (decision === 'BLOCK') {
        const blockedUntil = new Date(now.getTime() + securityConfig.mitigation.temporaryBlockMs);
        await prisma.ipTracking.upsert({
            where: { ipAddress: identifier },
            update: {
                isBlocked: true,
                blockedUntil,
                lastSeen: now,
                totalRequests: { increment: 1 }
            },
            create: {
                ipAddress: identifier,
                isBlocked: true,
                blockedUntil,
                lastSeen: now,
                totalRequests: 1
            }
        });
        res.status(403).json({
            success: false,
            message: "CRITICAL THREAT: Brute force behavior detected. IP temporarily blocked."
        });
        return true;

    } else if (decision === 'THROTTLE') {
        // Not persisted: THROTTLE is a soft, momentary penalty, not a
        // standing block worth recording in ipTracking.
        res.status(429).json({
            success: false,
            message: "Too many attempts. Please wait.",
            retryAfter: 15
        });
        return true;
    }

    // ALLOW/LOG require no mitigation. A row is written here only once a
    // device earns a BLOCK, so ipTracking stays a record of genuine
    // incidents rather than every request seen.
    if (existing && (!existing.isBlocked || (existing.blockedUntil && existing.blockedUntil <= now))) {
        // Lockout has expired - clear the stale flag so the dashboard stops
        // reporting the device as blocked. Best-effort; failure here does
        // not affect the current request.
        await prisma.ipTracking.update({
            where: { ipAddress: identifier },
            data: { isBlocked: false, blockedUntil: null }
        }).catch(err => console.error("Stale block cleanup failed:", err.message));
    }

    return false;
}
