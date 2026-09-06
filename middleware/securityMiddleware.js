import { getFeatures, updateFeatures } from "../core/monitor.js";
import { getBaseline, updateBaseline } from "../core/profiler.js";
import { computeScore, defaultWevaConfig } from "../core/scorer.js";
import { decideAction, defaultDecisionConfig } from "../core/decisionEngine.js";
import { applyMitigation } from "../core/mitigation.js";

/**
 * Builds the request pipeline stage that scores every request for
 * anomalous behavior and enforces the resulting mitigation verdict.
 *
 * Orchestrates the anomaly-detection subsystem end to end: derives the
 * request's behavioral features (core/monitor.js), compares them against
 * the device's learned baseline (core/profiler.js), computes an anomaly
 * score (core/scorer.js), resolves a mitigation decision
 * (core/decisionEngine.js), persists an auditable record of the
 * evaluation, and enforces the decision (core/mitigation.js).
 *
 * The behavioral state getFeatures()/getBaseline() read and write here -
 * per-device request history, login-attempt counts, and EMA baselines -
 * is backed by MemoryStateStore (core/stateStore.js) rather than the bare
 * objects those two modules used to hold directly, so a device that goes
 * idle for 30+ minutes is eventually evicted instead of sitting in memory
 * for the lifetime of the process. See core/monitor.js and
 * core/profiler.js.
 *
 * This module never imports Prisma (or any other storage client) itself:
 * persistence and identity lookup are delegated entirely to the
 * `auditSink` and `identityResolver` ports injected here (see
 * core/ports.js), and `ipTrackingStore` is passed straight through to
 * core/mitigation.js#applyMitigation. The default, Prisma-backed
 * implementations are constructed once in server.js via core/weva.js's
 * createWeva() and injected there - this file has no idea, and does not
 * need to know, what actually persists that state.
 *
 * @param {object} deps
 * @param {import("../core/ports.js").AuditSink} deps.auditSink
 * @param {import("../core/ports.js").IpTrackingStore} deps.ipTrackingStore
 * @param {import("../core/ports.js").IdentityResolver} deps.identityResolver
 * @param {object} [deps.wevaConfig] - Overrides for core/scorer.js#computeScore; defaults to defaultWevaConfig (this app's exact current tuning) when omitted.
 * @param {object} [deps.decisionConfig] - Overrides for core/decisionEngine.js#decideAction; defaults to defaultDecisionConfig when omitted.
 * @returns {import("express").RequestHandler} Express middleware. Calls
 *          `next()` unless the request was blocked or throttled.
 */
export function createSecurityMiddleware({ auditSink, ipTrackingStore, identityResolver, wevaConfig = defaultWevaConfig, decisionConfig = defaultDecisionConfig }) {
    return async function securityMiddleware(req, res, next) {
        const user = req.user?.email || "unauthenticated";
        const role = req.user?.role || "guest";

        let userId = null;
        if (req.user?.email) {
            try {
                const identity = await identityResolver.resolve(req.user.email);
                userId = identity?.id ?? null;
            } catch (err) {
                console.error("User ID resolution failed during security logging:", err.message);
                userId = null;
            }
        }

        const deviceId = req.headers["x-device-id"] || req.ip;

        // req.baseUrl + req.path, not req.path alone: Express rewrites req.url
        // (and so req.path) relative to the current mount point while
        // dispatching into a sub-router, restoring it afterward. Every
        // endpoint in this app is registered directly on `app` (e.g.
        // app.post("/api/students", ...) in server.js) EXCEPT /login and
        // /verify-otp, which live in routes/authRoutes.js and are reached via
        // app.use("/api", authRoutes) - so for exactly those two routes,
        // req.path alone resolves to "/login"/"/verify-otp" (the /api prefix
        // already stripped by that mount), which matches no entry in
        // core/scorer.js#endpointWeights and silently falls back to the
        // default endpoint weight (1x) instead of their configured 2x -
        // roughly doubling the number of attempts WEVA tolerates before
        // THROTTLE/BLOCK on precisely the two credential-verification
        // endpoints that need it most. req.baseUrl ("/api" inside that
        // sub-router, "" for a route registered directly on `app`) added back
        // reconstructs the full path either way.
        const endpoint = req.baseUrl + req.path;

        const currentFeatures = getFeatures(deviceId, endpoint);
        const baseline = getBaseline(deviceId);

        // The itemized factor breakdown is persisted alongside the score so
        // every decision remains independently auditable (see core/scorer.js).
        const { score, breakdown } = computeScore(currentFeatures, baseline, wevaConfig);
        const decision = decideAction(score, role, decisionConfig);

        console.log(`[SECURITY] Device: ${deviceId} | Target User: ${user} | Score: ${score} (${breakdown.formula}) | Decision: ${decision}`);

        const risk = decision === 'BLOCK' ? 'CRITICAL' : decision === 'THROTTLE' ? 'HIGH' : decision === 'LOG' ? 'MEDIUM' : 'LOW';

        // The " | " delimiter separates the human-readable narrative from the
        // machine-precise formula using one fixed sequence, so
        // public/admin_dashboard.js can split this column back into two
        // cleanly-styled pieces without a fragile regex (see fetchLogs()).
        const reasonText = `Device ${deviceId} triggered ${decision} | ${breakdown.formula}`;

        await auditSink.recordEvaluation({
            userEmail: user,
            userId,
            score,
            riskLevel: risk,
            actionTaken: decision,
            reason: reasonText,
            eventType: 'SECURITY_EVALUATION'
        });

        const blocked = await applyMitigation(decision, res, deviceId, ipTrackingStore);

        updateFeatures(deviceId, endpoint);
        updateBaseline(deviceId, currentFeatures);

        if (blocked) return;

        next();
    };
}
