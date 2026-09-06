/**
 * @fileoverview Default IpTrackingStore (see core/ports.js), backed by
 * Prisma's `ipTracking` table.
 *
 * Extracted from core/mitigation.js (which read/wrote this table to
 * enforce BLOCK verdicts) and middleware/ipWhitelistMiddleware.js (which
 * wrote it directly when a disallowed network origin was rejected). Both
 * now call this one class instead.
 */
export class PrismaIpTrackingStore {
    /** @param {import("@prisma/client").PrismaClient} prisma */
    constructor(prisma) {
        this.prisma = prisma;
    }

    /**
     * @param {string} identifier
     * @returns {Promise<import("../../core/ports.js").IpBlockStatus|null>}
     */
    async findStatus(identifier) {
        const row = await this.prisma.ipTracking.findUnique({ where: { ipAddress: identifier } });
        return row ? { isBlocked: row.isBlocked, blockedUntil: row.blockedUntil } : null;
    }

    /**
     * @param {string} identifier
     * @param {Date} blockedUntil
     * @returns {Promise<void>}
     */
    async block(identifier, blockedUntil) {
        const now = new Date();
        await this.prisma.ipTracking.upsert({
            where: { ipAddress: identifier },
            update: { isBlocked: true, blockedUntil, lastSeen: now, totalRequests: { increment: 1 } },
            create: { ipAddress: identifier, isBlocked: true, blockedUntil, lastSeen: now, totalRequests: 1 }
        });
    }

    /**
     * Lifts a stale block. Best-effort, matching the original inline
     * behavior this was extracted from: this is opportunistic cleanup
     * triggered by an unrelated request noticing a stale flag, not a
     * required side effect of that request, so a failure here is logged
     * and swallowed rather than surfaced to the caller.
     *
     * @param {string} identifier
     * @returns {Promise<void>}
     */
    async clear(identifier) {
        await this.prisma.ipTracking.update({
            where: { ipAddress: identifier },
            data: { isBlocked: false, blockedUntil: null }
        }).catch(err => console.error("[PrismaIpTrackingStore] Stale block cleanup failed:", err.message));
    }
}
