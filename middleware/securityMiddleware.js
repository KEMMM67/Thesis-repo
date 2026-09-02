import { getFeatures, updateFeatures } from "../core/monitor.js";
import { getBaseline, updateBaseline } from "../core/profiler.js";
import { computeScore } from "../core/scorer.js";
import { decideAction } from "../core/decisionEngine.js";
import { applyMitigation } from "../core/mitigation.js";
import prisma from "../config/prisma.js";

/**
 * Request pipeline stage that scores every request for anomalous behavior
 * and enforces the resulting mitigation verdict.
 *
 * Orchestrates the anomaly-detection subsystem end to end: derives the
 * request's behavioral features (core/monitor.js), compares them against
 * the device's learned baseline (core/profiler.js), computes an anomaly
 * score (core/scorer.js), resolves a mitigation decision
 * (core/decisionEngine.js), persists an auditable record of the
 * evaluation, and enforces the decision (core/mitigation.js).
 *
 * @param {import("express").Request} req
 * @param {import("express").Response} res
 * @param {import("express").NextFunction} next
 * @returns {Promise<void>} Calls `next()` unless the request was blocked or throttled.
 */
export const securityMiddleware = async (req, res, next) => {
    const user = req.user?.email || "unauthenticated";
    const role = req.user?.role || "guest";

    let userId = null;
    if (req.user?.email) {
        try {
            const resolvedUser = await prisma.user.findUnique({
                where: { email: req.user.email },
                select: { id: true }
            });
            userId = resolvedUser?.id ?? null;
        } catch (err) {
            console.error("User ID resolution failed during security logging:", err.message);
            userId = null;
        }
    }

    const deviceId = req.headers["x-device-id"] || req.ip;
    const endpoint = req.path;

    const currentFeatures = getFeatures(deviceId, endpoint);
    const baseline = getBaseline(deviceId);

    // The itemized factor breakdown is persisted alongside the score so
    // every decision remains independently auditable (see core/scorer.js).
    const { score, breakdown } = computeScore(currentFeatures, baseline);
    const decision = decideAction(score, role);

    console.log(`[SECURITY] Device: ${deviceId} | Target User: ${user} | Score: ${score} (${breakdown.formula}) | Decision: ${decision}`);

    let risk = decision === 'BLOCK' ? 'CRITICAL' : decision === 'THROTTLE' ? 'HIGH' : decision === 'LOG' ? 'MEDIUM' : 'LOW';

    // The " | " delimiter separates the human-readable narrative from the
    // machine-precise formula using one fixed sequence, so
    // public/admin_dashboard.js can split this column back into two
    // cleanly-styled pieces without a fragile regex (see fetchLogs()).
    const reasonText = `Device ${deviceId} triggered ${decision} | ${breakdown.formula}`;

    const results = await Promise.allSettled([
        prisma.anomalyScore.create({
            data: { userEmail: user, userId, score, riskLevel: risk }
        }),
        prisma.securityAction.create({
            data: {
                userEmail: user,
                userId,
                actionTaken: decision,
                reason: reasonText
            }
        }),
        prisma.behaviorLog.create({
            data: {
                userEmail: user,
                userId,
                eventType: 'SECURITY_EVALUATION',
                description: reasonText
            }
        })
    ]);

    const tableNames = ['anomaly_scores', 'security_actions', 'behavior_logs'];
    results.forEach((result, i) => {
        if (result.status === 'rejected') {
            console.error(`Audit log write failed (${tableNames[i]}):`, result.reason.message);
        }
    });

    const blocked = await applyMitigation(decision, res, deviceId);

    updateFeatures(deviceId, endpoint);
    updateBaseline(deviceId, currentFeatures);

    if (blocked) return;

    next();
};
