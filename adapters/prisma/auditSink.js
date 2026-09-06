/**
 * @fileoverview Default AuditSink (see core/ports.js), backed by Prisma.
 *
 * Extracted verbatim from the inline Promise.allSettled block that used to
 * live in middleware/securityMiddleware.js and, duplicated, in
 * middleware/ipWhitelistMiddleware.js#recordIntrusion - both wrote the
 * same three tables directly. They now both call this one class instead.
 */
export class PrismaAuditSink {
    /** @param {import("@prisma/client").PrismaClient} prisma */
    constructor(prisma) {
        this.prisma = prisma;
    }

    /**
     * Writes one WEVA verdict to the AnomalyScore, SecurityAction, and
     * BehaviorLog tables. The three writes run concurrently and
     * independently via Promise.allSettled: a failure in one (e.g. a
     * transient DB hiccup) must not prevent the other two from landing,
     * and none of the three failing should ever propagate to the caller -
     * a persistence problem in the audit trail must never be allowed to
     * break the security decision it is only trying to log.
     *
     * @param {import("../../core/ports.js").WevaEvaluation} evaluation
     * @returns {Promise<void>}
     */
    async recordEvaluation({ userEmail, userId, score, riskLevel, actionTaken, reason, eventType }) {
        const results = await Promise.allSettled([
            this.prisma.anomalyScore.create({ data: { userEmail, userId, score, riskLevel } }),
            this.prisma.securityAction.create({ data: { userEmail, userId, actionTaken, reason } }),
            this.prisma.behaviorLog.create({ data: { userEmail, userId, eventType, description: reason } })
        ]);

        const tableNames = ['anomaly_scores', 'security_actions', 'behavior_logs'];
        results.forEach((result, i) => {
            if (result.status === 'rejected') {
                console.error(`[PrismaAuditSink] Audit write failed (${tableNames[i]}):`, result.reason.message);
            }
        });
    }
}
