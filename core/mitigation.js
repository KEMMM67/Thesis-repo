import { securityConfig } from "../config/securityConfig.js";
import prisma from "../config/prisma.js";

// Applies penalties based on the Decision Engine's verdict. Persisted via
// prisma.ipTracking instead of an in-memory Map: blocks now survive a
// server restart, are queryable by the admin dashboard's Blocked
// Devices panel, and stay correct if this ever runs behind more than
// one server instance (an in-memory Map is per-process and silently
// diverges the moment there's a second one).
//
// SE NOTE on the "identifier" naming: this is called with `deviceId`
// (public/admin_dashboard.js's x-device-id header, falling back to
// req.ip - see core/monitor.js), not necessarily a real IP address, yet
// it's stored in a column literally named ipAddress. That mismatch is
// pre-existing to this feature - the in-memory blockedList Map this
// replaces was already keyed the same way - not something introduced
// here. Documented rather than silently carried forward.
export async function applyMitigation(decision, res, identifier) {
    const now = new Date();

    // Step 1: verify if this identifier is already serving a lockout
    // penalty from an EARLIER request, regardless of what the CURRENT
    // request's own decision is - an already-blocked device must stay
    // rejected even on a request that would otherwise score as
    // ALLOW/LOG.
    const existing = await prisma.ipTracking.findUnique({ where: { ipAddress: identifier } });

    if (existing?.isBlocked && existing.blockedUntil && existing.blockedUntil > now) {
        res.status(403).json({
            success: false,
            message: "CRITICAL THREAT: Brute force behavior detected. IP temporarily blocked."
        });
        return true;
    }

    // Step 2: enforce new penalties based on the current decision.
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
        // Issue a rate-limit warning and require a cooldown period.
        // Not persisted to ipTracking - THROTTLE is a soft, momentary
        // penalty (see core/mitigation.js's caller), not a standing
        // block worth tracking in the same table BLOCK writes to.
        res.status(429).json({
            success: false,
            message: "Too many attempts. Please wait.",
            retryAfter: 15
        });
        return true;
    }

    // ALLOW or LOG actions require no immediate mitigation and no
    // ipTracking write - a row only gets created/updated here the
    // moment a device actually earns a BLOCK, keeping this table a
    // record of genuine incidents rather than every request ever seen
    // (that volume already lives in AnomalyScore/BehaviorLog).
    if (existing && (!existing.isBlocked || (existing.blockedUntil && existing.blockedUntil <= now))) {
        // A previously-blocked device whose lockout has since expired -
        // clear the stale flag so it stops showing up as "blocked" in
        // the dashboard panel. Best-effort: failing this write doesn't
        // affect the current request either way.
        await prisma.ipTracking.update({
            where: { ipAddress: identifier },
            data: { isBlocked: false, blockedUntil: null }
        }).catch(err => console.error("Stale block cleanup failed:", err.message));
    }

    return false;
}
