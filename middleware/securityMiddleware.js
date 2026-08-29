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

    const score = computeScore(currentFeatures, baseline);
    const decision = decideAction(score, role);

    console.log(`[SECURITY] Device: ${deviceId} | Target User: ${user} | Score: ${score} | Decision: ${decision}`);

    let risk = decision === 'BLOCK' ? 'CRITICAL' : decision === 'THROTTLE' ? 'HIGH' : decision === 'LOG' ? 'MEDIUM' : 'LOW';

    const results = await Promise.allSettled([
        prisma.anomalyScore.create({
            data: { userEmail: user, userId, score, riskLevel: risk }
        }),
        prisma.securityAction.create({
            data: {
                userEmail: user,
                userId,
                actionTaken: decision,
                reason: `Device ${deviceId} triggered behavioral score of ${score}`
            }
        }),
        prisma.behaviorLog.create({
            data: {
                userEmail: user,
                userId,
                eventType: 'SECURITY_EVALUATION',
                description: `Triggered ${decision} on Device ${deviceId} with score ${score}`
            }
        })
    ]);

    const tableNames = ['anomaly_scores', 'security_actions', 'behavior_logs'];
    results.forEach((result, i) => {
        if (result.status === 'rejected') {
            console.error(`Audit log write failed (${tableNames[i]}):`, result.reason.message);
        }
    });

    const blocked = applyMitigation(decision, res, deviceId);

    updateFeatures(deviceId, endpoint);
    updateBaseline(deviceId, currentFeatures);

    if (blocked) return;

    next();
};