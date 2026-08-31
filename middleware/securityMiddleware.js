import { getFeatures, updateFeatures } from "../core/monitor.js";
import { getBaseline, updateBaseline } from "../core/profiler.js";
import { computeScore } from "../core/scorer.js";
import { decideAction } from "../core/decisionEngine.js";
import { applyMitigation } from "../core/mitigation.js";
import prisma from "../config/prisma.js";

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

    // computeScore() returns both the final score AND the itemized
    // factors that produced it (see core/scorer.js) - SE traceability
    // requirement: every decision this middleware makes has to be
    // reconstructable after the fact, not just visible in a console
    // that's no longer scrolled back to.
    const { score, breakdown } = computeScore(currentFeatures, baseline);
    const decision = decideAction(score, role);

    console.log(`[SECURITY] Device: ${deviceId} | Target User: ${user} | Score: ${score} (${breakdown.formula}) | Decision: ${decision}`);

    let risk = decision === 'BLOCK' ? 'CRITICAL' : decision === 'THROTTLE' ? 'HIGH' : decision === 'LOG' ? 'MEDIUM' : 'LOW';

    // The " | " delimiter is deliberate, not decorative: it separates a
    // human-readable narrative (left of it) from the machine-precise
    // formula (right of it) using one fixed, predictable character
    // sequence, so public/admin_dashboard.js can split this single text
    // column back into two cleanly-styled pieces without any fragile
    // regex - see fetchLogs() there.
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

    // applyMitigation() is now async - it reads/writes prisma.ipTracking
    // instead of an in-memory Map (see core/mitigation.js).
    const blocked = await applyMitigation(decision, res, deviceId);

    updateFeatures(deviceId, endpoint);
    updateBaseline(deviceId, currentFeatures);

    if (blocked) return;

    next();
};